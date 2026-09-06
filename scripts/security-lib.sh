#!/usr/bin/env bash
# Shared helpers for the security auditor (scripts/security-*.sh, scripts/secaudit.sh).
# Sourced, never executed. See docs/plan/secaudit.md for the design.
#
# Why a sourced lib when the rest of the repo has none: eight callers need the same six primitives
# (env reading, Komodo API, atomic state writes, scan bookkeeping, the backup interlock). Copying
# them per script is how the state format quietly diverges between scans.

[ -n "${BASH_SOURCE[0]:-}" ] || { echo "security-lib.sh must be sourced" >&2; exit 1; }
SEC_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEC_STATE_DIR="$SEC_REPO_DIR/security/state"
SEC_PROJECT="manager-komodo"          # compose project == docker network name (set explicitly in
                                      # docker-compose.yml, so it is not project-prefixed)
SEC_CURL_IMAGE="curlimages/curl:8.11.1"   # latest stable, already present on this host

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
sec_log()  { echo "${c_grn}[+]${c_rst} $*"; }
sec_warn() { echo "${c_yel}[!]${c_rst} $*" >&2; }
sec_die()  { echo "${c_red}[x]${c_rst} $*" >&2; exit 1; }

# Read one key from .env. It is a compose env file (KEY=value, values NOT shell-quoted, some
# containing spaces and &), so it must NOT be sourced as shell — we parse the exact keys we need.
# Same implementation as scripts/setup-deploy-procedure.sh; environment values win over .env.
env_get() {
  [ -f "$SEC_REPO_DIR/.env" ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$SEC_REPO_DIR/.env" | head -n1 \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

sec_load_env() {
  KOMODO_API_KEY="${KOMODO_API_KEY:-$(env_get KOMODO_API_KEY)}"
  KOMODO_API_SECRET="${KOMODO_API_SECRET:-$(env_get KOMODO_API_SECRET)}"
  : "${KOMODO_API_KEY:?KOMODO_API_KEY not set (.env)}"
  : "${KOMODO_API_SECRET:?KOMODO_API_SECRET not set (.env)}"
  export KOMODO_API_KEY KOMODO_API_SECRET
  SECAUDIT_ENABLED="${SECAUDIT_ENABLED:-$(env_get SECAUDIT_ENABLED)}"
  SECAUDIT_ENABLED="${SECAUDIT_ENABLED:-true}"
  SECAUDIT_MANAGER_PUBLIC_IP="${SECAUDIT_MANAGER_PUBLIC_IP:-$(env_get PUBLIC_IP)}"
  SECAUDIT_MANAGER_MESH_IP="${SECAUDIT_MANAGER_MESH_IP:-100.64.0.1}"
  SECAUDIT_RETENTION_DAYS="${SECAUDIT_RETENTION_DAYS:-$(env_get SECAUDIT_RETENTION_DAYS)}"
  SECAUDIT_RETENTION_DAYS="${SECAUDIT_RETENTION_DAYS:-90}"
}

# Komodo API call. $1 = path (e.g. read/ListServers), $2 = JSON body (default {}).
# Goes to http://komodo-core:9120 over the compose network, NOT to https://komodo.apps.internal:
# the internal certs are 24h step-ca certs, and the auditor must not go blind precisely when
# internal TLS is the thing that broke.
# The two credentials are passed as bare `-e NAME`, so their VALUES never appear in argv (argv is
# visible in `ps` and in `docker inspect`); the request body arrives on stdin. The only strings the
# container shell expands are its own env vars, so nothing here needs escaping.
kapi() {
  local path="$1" body="${2-}" timeout="${3:-20}"
  [ -n "$body" ] || body='{}'
  printf '%s' "$body" | docker run --rm -i --network "$SEC_PROJECT" \
      -e KOMODO_API_KEY -e KOMODO_API_SECRET \
      -e KAPI_URL="http://komodo-core:9120/${path}" -e KAPI_TIMEOUT="$timeout" \
      --entrypoint sh "$SEC_CURL_IMAGE" -c \
      'exec curl -fsS -m "$KAPI_TIMEOUT" \
         -H "Content-Type: application/json" \
         -H "X-Api-Key: $KOMODO_API_KEY" -H "X-Api-Secret: $KOMODO_API_SECRET" \
         --data-binary @- "$KAPI_URL"'
}

# Atomic state write: content on stdin, path relative to security/state. tmp + mv on the same
# filesystem, because the exporter reads these files while a scan replaces them — a partial read of
# a half-written findings file would show up as findings vanishing.
sec_state_write() {
  local rel="$1" dst="$SEC_STATE_DIR/$1" tmp
  mkdir -p "$(dirname "$dst")"
  tmp="$(mktemp "$(dirname "$dst")/.$(basename "$dst").XXXXXX")"
  cat > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$dst"
  sec_log "wrote state/$rel"
}

sec_state_path() { echo "$SEC_STATE_DIR/$1"; }

# --- scan bookkeeping -------------------------------------------------------------------------
# One file, state/scan-status.json, holding lifecycle facts for every scan: when it last ran, when
# it last SUCCEEDED (deliberately separate — a failing scan must not look fresh), how long it took,
# how many targets it saw, and a cumulative skip counter per reason.
SEC_SCAN=""; SEC_SCAN_HOST=""; SEC_SCAN_T0=""

_sec_status_update() {   # jq filter on stdin-less: $1 = jq program, rest = --argjson/--arg pairs
  local f="$SEC_STATE_DIR/scan-status.json" tmp prog="$1"; shift
  mkdir -p "$SEC_STATE_DIR"
  [ -s "$f" ] || echo '{"schema":1,"scans":{},"skips":{}}' > "$f"
  tmp="$(mktemp "$SEC_STATE_DIR/.scan-status.XXXXXX")"
  if jq "$@" "$prog" "$f" > "$tmp" 2>/dev/null; then
    chmod 0644 "$tmp"; mv -f "$tmp" "$f"
  else
    rm -f "$tmp"; sec_warn "scan-status update failed (kept previous)"
  fi
}

sec_scan_begin() {   # $1 = scan name, $2 = host (default manager)
  SEC_SCAN="$1"; SEC_SCAN_HOST="${2:-manager}"; SEC_SCAN_T0="$(date +%s.%N)"
  _sec_status_update \
    '.scans[$k] = ((.scans[$k] // {"scan":$s,"host":$h}) + {"scan":$s,"host":$h,"last_run":$now})' \
    --arg k "$1|${2:-manager}" --arg s "$1" --arg h "${2:-manager}" \
    --argjson now "$(date +%s)"
}

sec_scan_end() {     # $1 = status (1 ok / 0 fail), $2 = target count
  local dur; dur="$(awk -v a="$SEC_SCAN_T0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.3f", b-a}')"
  local prog='.scans[$k] += {"status":$st,"duration":$dur,"targets":$tg}'
  [ "$1" = "1" ] && prog="$prog"' | .scans[$k] += {"last_success":$now}'
  _sec_status_update "$prog" \
    --arg k "$SEC_SCAN|$SEC_SCAN_HOST" --argjson st "$1" \
    --argjson dur "$dur" --argjson tg "${2:-0}" --argjson now "$(date +%s)"
}

# A skipped scan is NOT a failed scan and must not look like a fresh one either: it bumps a counter
# and leaves last_success alone, so staleness is what eventually alerts.
sec_scan_skip() {    # $1 = scan, $2 = reason
  _sec_status_update '.skips[$k] = ((.skips[$k] // 0) + 1)' --arg k "$1|$2"
  sec_warn "scan $1 skipped: $2"
}

# --- guards ------------------------------------------------------------------------------------
# backup-manager.sh STOPS step-ca, grafana and komodo-core/ferretdb/postgres at 04:00 UTC. A scan
# overlapping that window reports false "port closed" / "cert invalid" and fails discovery, so we
# skip instead. NOT `Conflicts=manager-backup.service` in the unit — that would stop the backup.
sec_require_no_backup() {   # $1 = scan name
  if systemctl is-active --quiet manager-backup.service 2>/dev/null; then
    sec_scan_skip "$1" backup_running
    return 1
  fi
  return 0
}
