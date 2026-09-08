#!/usr/bin/env bash
# Print each app host's maintenance-silence URL, to paste into that host's Komodo `environment`
# as KOMODO_ALERT_SILENCE_URL. Read-only: it writes nothing, here or in Komodo.
#
# The token is HMAC-SHA256(MAINTENANCE_HMAC_KEY, <host>) truncated to 32 hex chars, and it lives in
# the URL PATH so the application's scripts/update.sh needs no change -- it already builds its
# request as "${KOMODO_ALERT_SILENCE_URL}/start". The manager stores no token: it re-derives and
# compares in constant time on every request (provisioning/server.py, maintenance_host_for_token).
#
# Why a token rather than the caller's mesh address, which would need no secret at all: the address
# does not survive the trip. Measured 2026-09-08 -- a request from an app host reaches Traefik with
# X-Forwarded-For 172.18.0.1, the manager's Docker bridge gateway, because dockerd's userland proxy
# terminates the connection and opens a fresh one. Every host looks identical at the application
# layer, so an address-based check authenticates nobody. See docs/APP-MAINTENANCE-SILENCE.md.
#
# It is a PER-HOST value, so it goes in that host's Komodo environment and never in an APPVAR_
# (those are fleet-wide, which is exactly what a per-host secret must not be).
#
# Usage: scripts/setup-maintenance-tokens.sh [--host <name>]
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --host) ONLY="${2:?--host needs a name}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

env_get() {
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | head -n1 \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
KEY="${MAINTENANCE_HMAC_KEY:-$(env_get MAINTENANCE_HMAC_KEY)}"
[ -n "$KEY" ] || { echo "MAINTENANCE_HMAC_KEY not set (.env)" >&2; exit 1; }
BASE="${MAINTENANCE_BASE_URL:-https://apps.internal/maintenance/silence}"

TARGETS=security/state/targets.json
[ -f "$TARGETS" ] || { echo "$TARGETS missing — run scripts/security-discover.sh first" >&2; exit 1; }

# The host list comes from the same file the server checks tokens against, so a host that is not
# in it would be refused even with a correct token. Deriving both from one source keeps them from
# disagreeing.
python3 - "$KEY" "$BASE" "$ONLY" "$TARGETS" <<'PY'
import hashlib, hmac, json, sys
key, base, only, path = sys.argv[1:5]
with open(path) as fh:
    targets = json.load(fh).get("targets", [])
rows = [t for t in targets if t.get("role") == "segcore" and (not only or t.get("host") == only)]
if not rows:
    print(f"no app host matched{' ' + only if only else ''}", file=sys.stderr)
    raise SystemExit(1)
for t in rows:
    host = t["host"]
    tok = hmac.new(key.encode(), host.encode(), hashlib.sha256).hexdigest()[:32]
    print(f"{host}:")
    print(f"  KOMODO_ALERT_SILENCE_URL={base}/{tok}")
PY
