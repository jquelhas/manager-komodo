#!/usr/bin/env bash
# Generate a one-time, web-delivered onboarding link for a new application host.
#
# Run on the MANAGER (as the operator). It:
#   1. creates a one-shot Headscale pre-auth key (tag:<role>, short TTL, reusable=false),
#   2. renders a per-host install script = a small preamble + bootstrap/onboard-host.sh (verbatim),
#   3. writes it to the provisioning store under a random v4 UUID,
#   4. prints the single command to paste on the new host.
#
# The provisioning service (Traefik -> provisioning container) serves it once at
# https://<domain>/provisioning/<uuid>/install.sh and the host burns it on completion; a TTL
# is the backstop. The UUID URL is the capability/secret.
#
# Usage: ./add-host.sh [--role gims-app] [--ttl 5m] [--hostname-default <name>]
#                      [--login-server <url>] [--core-pubkey <b64>] [--periphery-version <vX>]

set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

ROLE="gims-app"
TTL="5m"
HOSTNAME_DEFAULT=""
LOGIN_SERVER="https://komodo.segcore.eu"
CORE_PUBKEY="MCowBQYDK2VuAyEAq4h7qO1p9pLMSxUgADHXY8IYtUnhcTwpLUyiNiuT2y8="
PERIPHERY_VERSION="v2.2.0"
STORE="${REPO_DIR}/provisioning/store"

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
info() { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_yel}[!]${c_rst} $*"; }
die()  { echo "${c_red}[x]${c_rst} $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --ttl) TTL="$2"; shift 2 ;;
    --hostname-default) HOSTNAME_DEFAULT="$2"; shift 2 ;;
    --login-server) LOGIN_SERVER="$2"; shift 2 ;;
    --core-pubkey) CORE_PUBKEY="$2"; shift 2 ;;
    --periphery-version) PERIPHERY_VERSION="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# ---- Preconditions ----
command -v docker  >/dev/null 2>&1 || die "docker not found."
command -v python3 >/dev/null 2>&1 || die "python3 not found."
docker ps --format '{{.Names}}' | grep -qx manager-headscale || die "manager-headscale is not running."
grep -q "tag:${ROLE}" docker/headscale/acl.hujson \
  || die "tag:${ROLE} is not an owned tag in docker/headscale/acl.hujson."
[ -d "$STORE" ] || die "store dir $STORE missing (bring the provisioning service up first)."
[ -w "$STORE" ] || die "store dir $STORE not writable by $(id -un)."

# TTL in seconds (headscale accepts s/m/h; d is not a Go duration unit).
TTL_SECONDS="$(python3 - "$TTL" <<'PY'
import re, sys
m = re.match(r'^(\d+)([smh])$', sys.argv[1])
if not m: sys.exit("invalid --ttl (use e.g. 30s, 5m, 1h)")
print(int(m.group(1)) * {'s':1,'m':60,'h':3600}[m.group(2)])
PY
)"

# ---- Generate UUID + one-shot pre-auth key ----
UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
info "Provisioning UUID: $UUID"

KEY_JSON="$(docker exec manager-headscale headscale preauthkeys create \
  --user 1 --tags "tag:${ROLE}" --expiration "$TTL" --reusable=false --output json)"
AUTH_KEY="$(printf '%s' "$KEY_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["key"])')"
[ -n "$AUTH_KEY" ] || die "failed to create/parse Headscale pre-auth key."

INSTALL_URL="${LOGIN_SERVER%/}/provisioning/${UUID}/install.sh"
COMPLETE_URL="${LOGIN_SERVER%/}/provisioning/${UUID}/complete"

# ---- Render served install.sh = preamble + verbatim onboard-host.sh ----
TMP="$(mktemp -d "${STORE}/.tmp.XXXXXX")"
{
  echo '#!/usr/bin/env bash'
  echo "export KOMODO_AUTH_KEY='${AUTH_KEY}'"
  echo "export KOMODO_LOGIN_SERVER='${LOGIN_SERVER}'"
  echo "export KOMODO_CORE_PUBKEY='${CORE_PUBKEY}'"
  echo "export KOMODO_ROLE='${ROLE}'"
  [ -n "$HOSTNAME_DEFAULT" ] && echo "export KOMODO_HOSTNAME_DEFAULT='${HOSTNAME_DEFAULT}'"
  echo "export PERIPHERY_VERSION='${PERIPHERY_VERSION}'"
  echo "export KOMODO_COMPLETE_URL='${COMPLETE_URL}'"
  echo '# ---- bootstrap/onboard-host.sh (verbatim) ----'
  cat "${REPO_DIR}/bootstrap/onboard-host.sh"
} > "${TMP}/install.sh"
chmod 600 "${TMP}/install.sh"

NOW="$(date -u +%s)"
cat > "${TMP}/meta.json" <<JSON
{"created_at": ${NOW}, "expires_at": $((NOW + TTL_SECONDS)), "role": "${ROLE}", "status": "active"}
JSON

chmod 700 "$TMP"
mv "$TMP" "${STORE}/${UUID}"

# ---- Output ----
echo
info "Onboarding link ready (role: tag:${ROLE}, expires in ${TTL})."
echo
echo "  Run this on the NEW host (Ubuntu/Debian, as root):"
echo
echo "    sudo bash -c \"\$(curl -fsSL ${INSTALL_URL})\""
echo
echo "  It will prompt for the hostname (default: the host's own \$(hostname))."
echo "  The link burns itself when onboarding completes; otherwise it expires in ${TTL}."
echo
echo "  Revoke early:  rm -rf ${STORE}/${UUID}  &&  docker exec manager-headscale headscale preauthkeys expire <id>"
