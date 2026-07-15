#!/usr/bin/env bash
# Backup the manager-komodo control-plane state to S3, encrypted.
#
# What it captures (the whole recoverable state of the manager):
#   - .env                      -> secrets (KOMODO/GRAFANA/DB passwords, BACKUP_MASTER_KEY, ...)
#   - step-ca volume            -> CRITICAL: root+intermediate CA, keys, config, issued-cert db
#   - headscale volume          -> SQLite db + noise/machine private keys
#   - grafana volume            -> grafana.db (users, api keys, dashboards state)
#   - komodo postgres volume    -> FerretDB backing store (all Komodo data)
#   - komodo ferretdb state     -> FerretDB metadata
#   - komodo core keys volume   -> Core's keypair (periphery trust)
#   - traefik certs             -> acme-*.json (LE + step-ca) + step-ca-root.crt
#   - victoriametrics snapshot  -> TSDB (taken live via the snapshot API)
#
# The critical pair for disaster recovery is (step-ca root + .env). Without both, restore is
# impossible without re-issuing every internal cert and regenerating every secret.
#
# Consistency: VictoriaMetrics is snapshotted live (atomic). The embedded-DB services are
# briefly stopped while their volumes are tar'd (a few seconds; the WireGuard data plane and the
# public Traefik stay up — stopping Headscale does not drop existing mesh sessions).
#
# Encryption: tar.gz piped through openssl AES-256-CBC (PBKDF2). The passphrase is
# BACKUP_MASTER_KEY. IMPORTANT: that key lives in .env, and .env is INSIDE the encrypted
# archive — so restore needs the key OUT-OF-BAND. Store BACKUP_MASTER_KEY in a password manager,
# never rely on recovering it from a backup.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# ---- Config from .env (read specific keys safely; .env may contain unquoted spaces) ----
env_get() { grep -E "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2- || true; }

MASTER_KEY="$(env_get BACKUP_MASTER_KEY)"
S3_ENDPOINT="$(env_get BACKUP_S3_ENDPOINT)"
S3_REGION="$(env_get BACKUP_S3_REGION)"
S3_BUCKET="$(env_get BACKUP_S3_BUCKET)"
S3_PREFIX="$(env_get BACKUP_S3_PREFIX)"; S3_PREFIX="${S3_PREFIX:-manager-komodo}"
S3_ACCESS_KEY="$(env_get BACKUP_S3_ACCESS_KEY)"
S3_SECRET_KEY="$(env_get BACKUP_S3_SECRET_KEY)"
# Retention is enforced by the bucket (Object Lock + Lifecycle), not here — see section 6.

for v in MASTER_KEY S3_ENDPOINT S3_BUCKET S3_ACCESS_KEY S3_SECRET_KEY; do
  [ -n "${!v}" ] || { echo "FATAL: BACKUP_${v#MASTER_} / ${v} not set in .env" >&2; exit 1; }
done

PROJECT="manager-komodo"        # docker compose project name (volumes are ${PROJECT}_<name>)
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
STAGE="$WORK/${PROJECT}-${STAMP}"
mkdir -p "$STAGE"
trap 'rm -rf "$WORK"' EXIT

log() { echo "[backup $(date -u +%H:%M:%S)] $*"; }

# Tar a named docker volume into the stage (read-only mount, via a throwaway alpine).
dump_volume() {
  local vol="$1" out="$2"
  docker run --rm -v "${PROJECT}_${vol}:/src:ro" -v "$STAGE:/dst" alpine \
    tar czf "/dst/${out}" -C /src .
}

# ---- 1. VictoriaMetrics: live snapshot, then tar just that snapshot ----
log "VictoriaMetrics snapshot..."
SNAP="$(docker run --rm --network "$PROJECT" alpine \
  wget -qO- 'http://victoriametrics:8428/snapshot/create' | grep -o '"snapshot":"[^"]*"' | cut -d'"' -f4)"
if [ -n "$SNAP" ]; then
  docker run --rm -v "${PROJECT}_victoriametrics-data:/src:ro" -v "$STAGE:/dst" alpine \
    tar czf /dst/victoriametrics-snapshot.tar.gz -C "/src/snapshots/$SNAP" .
  docker run --rm --network "$PROJECT" alpine \
    wget -qO- "http://victoriametrics:8428/snapshot/delete?snapshot=$SNAP" >/dev/null || true
  echo "$SNAP" > "$STAGE/victoriametrics-snapshot.name"
else
  log "WARN: VM snapshot failed (VM down?), skipping TSDB"
fi

# ---- 2. Traefik certs (bind mount, rare writes) + .env ----
log "Traefik certs + .env..."
tar czf "$STAGE/traefik-certs.tar.gz" -C "$REPO_DIR/docker/traefik/certs" . 2>/dev/null || true
cp .env "$STAGE/env.backup"

# ---- 3. Embedded-DB services: brief quiesce, then tar volumes ----
QUIESCE="headscale grafana step-ca komodo-core komodo-ferretdb komodo-postgres"
log "Stopping [$QUIESCE] for a consistent copy..."
docker compose stop $QUIESCE >/dev/null 2>&1
STOPPED=1
restart() {
  if [ "${STOPPED:-0}" = 1 ]; then
    log "Starting services back up..."
    docker compose start $QUIESCE >/dev/null 2>&1 || true
    STOPPED=0
  fi
  return 0
}
trap 'restart; rm -rf "$WORK"' EXIT

dump_volume stepca-data           stepca-data.tar.gz
dump_volume headscale-data        headscale-data.tar.gz
dump_volume grafana-data          grafana-data.tar.gz
dump_volume komodo-postgres-data  komodo-postgres-data.tar.gz
dump_volume komodo-ferretdb-state komodo-ferretdb-state.tar.gz
dump_volume komodo-core-keys      komodo-core-keys.tar.gz

restart   # bring services back before the (slower) encrypt+upload

# ---- 4. Pack + encrypt ----
log "Packing and encrypting..."
ARCHIVE="$WORK/${PROJECT}-${STAMP}.tar.gz"
tar czf "$ARCHIVE" -C "$WORK" "${PROJECT}-${STAMP}"
ENC="${ARCHIVE}.enc"
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -in "$ARCHIVE" -out "$ENC" -pass "pass:${MASTER_KEY}"
sha256sum "$ENC" | cut -d' ' -f1 > "${ENC}.sha256"
SIZE="$(du -h "$ENC" | cut -f1)"
log "Encrypted archive: $(basename "$ENC") ($SIZE)"

# ---- 5. Upload to S3 (rclone on-the-fly S3 backend, no config file) ----
rc() { rclone --s3-provider=Other --s3-access-key-id="$S3_ACCESS_KEY" \
  --s3-secret-access-key="$S3_SECRET_KEY" --s3-endpoint="$S3_ENDPOINT" \
  ${S3_REGION:+--s3-region="$S3_REGION"} "$@"; }
DEST=":s3:${S3_BUCKET}/${S3_PREFIX}"
log "Uploading to ${DEST}/ ..."
rc copyto "$ENC"          "${DEST}/$(basename "$ENC")"
rc copyto "${ENC}.sha256" "${DEST}/$(basename "$ENC").sha256"

# ---- 6. Retention ----
# Retention is enforced SERVER-SIDE by the bucket, not by this script:
#   - Object Lock (COMPLIANCE, 30d): objects are immutable for 30 days (cannot be deleted).
#   - Lifecycle expiration (30d): objects are auto-deleted at 30 days.
# This is more reliable than client-side pruning (runs even if a backup is skipped) and avoids
# fighting Object Lock (client deletes of <30d objects would fail anyway). No prune here.

log "DONE: ${DEST}/$(basename "$ENC")"
