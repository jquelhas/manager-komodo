#!/usr/bin/env bash
# Restore manager-komodo control-plane state from an encrypted S3 backup.
#
# Config comes from ENVIRONMENT VARIABLES, not .env — on a fresh manager .env does not exist
# yet (it is restored FROM the backup). Export these before running:
#   BACKUP_MASTER_KEY      (out-of-band; the passphrase used at backup time)
#   BACKUP_S3_ENDPOINT BACKUP_S3_BUCKET BACKUP_S3_ACCESS_KEY BACKUP_S3_SECRET_KEY
#   BACKUP_S3_PREFIX       (default manager-komodo)
#   BACKUP_S3_REGION       (optional)
#   BACKUP_FILE            (optional; specific archive name, else the newest is used)
#
# Flags: --force to skip the confirmation prompt; --integrity-only to just download+decrypt+
# verify the archive WITHOUT touching any live volume (safe to run on a working manager).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

FORCE=0; INTEGRITY_ONLY=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --integrity-only) INTEGRITY_ONLY=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

: "${BACKUP_MASTER_KEY:?set BACKUP_MASTER_KEY}"
: "${BACKUP_S3_ENDPOINT:?set BACKUP_S3_ENDPOINT}"
: "${BACKUP_S3_BUCKET:?set BACKUP_S3_BUCKET}"
: "${BACKUP_S3_ACCESS_KEY:?set BACKUP_S3_ACCESS_KEY}"
: "${BACKUP_S3_SECRET_KEY:?set BACKUP_S3_SECRET_KEY}"
S3_PREFIX="${BACKUP_S3_PREFIX:-manager-komodo}"
PROJECT="manager-komodo"

log() { echo "[restore $(date -u +%H:%M:%S)] $*"; }
rc() { rclone --s3-provider=Other --s3-access-key-id="$BACKUP_S3_ACCESS_KEY" \
  --s3-secret-access-key="$BACKUP_S3_SECRET_KEY" --s3-endpoint="$BACKUP_S3_ENDPOINT" \
  ${BACKUP_S3_REGION:+--s3-region="$BACKUP_S3_REGION"} "$@"; }
DEST=":s3:${BACKUP_S3_BUCKET}/${S3_PREFIX}"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---- Pick the archive ----
FILE="${BACKUP_FILE:-}"
if [ -z "$FILE" ]; then
  FILE="$(rc lsf "$DEST" --include '*.tar.gz.enc' | sort | tail -1)"
  [ -n "$FILE" ] || { echo "FATAL: no *.tar.gz.enc found in $DEST" >&2; exit 1; }
fi
log "Selected archive: $FILE"

# ---- Download + verify + decrypt ----
rc copyto "${DEST}/${FILE}"          "$WORK/${FILE}"
rc copyto "${DEST}/${FILE}.sha256"   "$WORK/${FILE}.sha256" 2>/dev/null || true
if [ -f "$WORK/${FILE}.sha256" ]; then
  (cd "$WORK" && echo "$(cat "${FILE}.sha256")  ${FILE}" | sha256sum -c -) \
    && log "sha256 OK" || { echo "FATAL: sha256 mismatch" >&2; exit 1; }
fi
log "Decrypting..."
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -in "$WORK/${FILE}" -out "$WORK/archive.tar.gz" -pass "pass:${BACKUP_MASTER_KEY}" \
  || { echo "FATAL: decrypt failed (wrong BACKUP_MASTER_KEY?)" >&2; exit 1; }
mkdir -p "$WORK/x"; tar xzf "$WORK/archive.tar.gz" -C "$WORK/x"
STAGE="$(echo "$WORK"/x/${PROJECT}-*)"
[ -d "$STAGE" ] || { echo "FATAL: unexpected archive layout" >&2; exit 1; }
log "Archive contents:"; ls -1 "$STAGE" | sed 's/^/    /'

if [ "$INTEGRITY_ONLY" = 1 ]; then
  log "--integrity-only: verified download+decrypt+untar OK. No changes made."
  exit 0
fi

# ---- Confirm (destructive) ----
if [ "$FORCE" != 1 ]; then
  echo
  echo "This will STOP the stack and OVERWRITE the live volumes and .env with the backup."
  read -r -p "Type 'restore' to proceed: " ans
  [ "$ans" = "restore" ] || { echo "Aborted."; exit 1; }
fi

# ---- Restore .env + traefik certs ----
log "Restoring .env..."
cp "$STAGE/env.backup" "$REPO_DIR/.env"; chmod 600 "$REPO_DIR/.env"
if [ -f "$STAGE/traefik-certs.tar.gz" ]; then
  log "Restoring traefik certs..."
  mkdir -p "$REPO_DIR/docker/traefik/certs"
  tar xzf "$STAGE/traefik-certs.tar.gz" -C "$REPO_DIR/docker/traefik/certs"
fi

# ---- Stop stack, restore volumes ----
log "Stopping stack..."
docker compose down >/dev/null 2>&1 || true

restore_volume() {
  local vol="$1" file="$2"
  [ -f "$STAGE/$file" ] || { log "  skip $vol (no $file in archive)"; return; }
  log "  restoring volume $vol"
  docker volume create "${PROJECT}_${vol}" >/dev/null
  docker run --rm -v "${PROJECT}_${vol}:/dst" -v "$STAGE:/src:ro" alpine sh -c \
    'rm -rf /dst/* /dst/..?* /dst/.[!.]* 2>/dev/null; tar xzf "/src/'"$file"'" -C /dst'
}

restore_volume stepca-data           stepca-data.tar.gz
restore_volume headscale-data        headscale-data.tar.gz
restore_volume grafana-data          grafana-data.tar.gz
restore_volume komodo-postgres-data  komodo-postgres-data.tar.gz
restore_volume komodo-ferretdb-state komodo-ferretdb-state.tar.gz
restore_volume komodo-core-keys      komodo-core-keys.tar.gz

# VictoriaMetrics snapshot -> data dir
if [ -f "$STAGE/victoriametrics-snapshot.tar.gz" ]; then
  log "  restoring VictoriaMetrics snapshot"
  docker volume create "${PROJECT}_victoriametrics-data" >/dev/null
  docker run --rm -v "${PROJECT}_victoriametrics-data:/dst" -v "$STAGE:/src:ro" alpine sh -c \
    'rm -rf /dst/* /dst/..?* /dst/.[!.]* 2>/dev/null; tar xzf /src/victoriametrics-snapshot.tar.gz -C /dst'
fi

log "Starting stack..."
docker compose up -d

log "DONE. Verify: services healthy, https://komodo.apps.internal reachable, mesh nodes present."
log "NOTE: if the manager's public IP changed, update PUBLIC_IP in .env and the DNS A record,"
log "      and the tailscale clients reconnect automatically as long as Headscale keys are intact."
