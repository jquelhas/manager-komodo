#!/usr/bin/env bash
# Install (idempotent) the SEGCORE deploy Procedure and its two Alertmanager-silence Actions into
# Komodo. Run on the MANAGER (as the operator) — same context as the CreateAlerter call in
# docs/INSTRUCTIONS.md. Safe to re-run: it updates the resources in place.
#
# Creates / updates:
#   - Action    segcore-silence-on   <- docker/komodo/actions/segcore-silence-on.ts
#   - Action    segcore-silence-off  <- docker/komodo/actions/segcore-silence-off.ts
#   - Procedure deploy-segcore: [silence-on] -> [BatchPullRepo segcore-*] -> [silence-off]
#
# After this, deploy the fleet by running the `deploy-segcore` Procedure (Komodo UI / webhook):
# it silences the SEGCORE alerts for the rebuild window automatically, so no backend down/up
# e-mails. A bare Repo Pull does NOT silence.
#
# Env (from .env or the environment):
#   KOMODO_API_KEY, KOMODO_API_SECRET   required
#   KOMODO_URL                          default https://komodo.apps.internal
#   KOMODO_CACERT                       optional CA bundle for curl (--cacert)
#   KOMODO_INSECURE=1                   skip TLS verification (curl -k); not recommended

set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
info() { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_yel}[!]${c_rst} $*"; }
die()  { echo "${c_red}[x]${c_rst} $*" >&2; exit 1; }

command -v jq   >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

# Read specific keys from .env. It is a docker-compose env file (KEY=value, values NOT shell-quoted
# and some contain spaces/&, e.g. the step-ca org), so we must NOT source it as shell — we parse the
# exact keys we need. Existing environment values win over .env.
env_get() {
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | head -n1 \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
KOMODO_API_KEY="${KOMODO_API_KEY:-$(env_get KOMODO_API_KEY)}"
KOMODO_API_SECRET="${KOMODO_API_SECRET:-$(env_get KOMODO_API_SECRET)}"
KOMODO_URL="${KOMODO_URL:-$(env_get KOMODO_URL)}"; KOMODO_URL="${KOMODO_URL:-https://komodo.apps.internal}"
: "${KOMODO_API_KEY:?KOMODO_API_KEY not set (.env)}"
: "${KOMODO_API_SECRET:?KOMODO_API_SECRET not set (.env)}"

# komodo.apps.internal is served with a step-ca cert the host doesn't trust by default. Use the
# repo's copy of the step-ca root as the CA bundle unless the operator overrides KOMODO_CACERT.
: "${KOMODO_CACERT:=$REPO_DIR/docker/traefik/certs/step-ca-root.crt}"

CURL_OPTS=(-fsS --max-time 20)
if [ "${KOMODO_INSECURE:-0}" = "1" ]; then
  CURL_OPTS+=(-k)
elif [ -n "$KOMODO_CACERT" ] && [ -f "$KOMODO_CACERT" ]; then
  CURL_OPTS+=(--cacert "$KOMODO_CACERT")
fi

ACTION_ON="$REPO_DIR/docker/komodo/actions/segcore-silence-on.ts"
ACTION_OFF="$REPO_DIR/docker/komodo/actions/segcore-silence-off.ts"
[ -f "$ACTION_ON" ]  || die "missing $ACTION_ON"
[ -f "$ACTION_OFF" ] || die "missing $ACTION_OFF"

# POST $2 (JSON) to the Komodo API endpoint $1 (e.g. write/CreateAction); echoes the response body.
kapi() {
  curl "${CURL_OPTS[@]}" "$KOMODO_URL/$1" \
    -H "X-Api-Key: $KOMODO_API_KEY" -H "X-Api-Secret: $KOMODO_API_SECRET" \
    -H 'Content-Type: application/json' -d "$2"
}

# Resolve a resource id by name from a Komodo list endpoint. $1 = read endpoint, $2 = name.
find_id() {
  kapi "$1" '{}' | jq -r --arg n "$2" 'map(select(.name==$n))[0] | (.id // ._id["$oid"] // empty)'
}

# Preflight: fail fast (and clearly) on bad creds / unreachable Core, so the create-vs-update
# decision below can trust that an empty id really means "does not exist".
kapi read/ListActions '{}' >/dev/null \
  || die "cannot reach the Komodo API at $KOMODO_URL (check KOMODO_URL / creds / step-ca trust)"

# Create the action if absent, else update its file_contents in place. $1 = name, $2 = .ts path.
ensure_action() {
  local name="$1" file="$2" cfg id
  cfg="$(jq -n --rawfile fc "$file" '{file_contents:$fc, webhook_enabled:false}')"
  id="$(find_id read/ListActions "$name")"
  if [ -n "$id" ]; then
    kapi write/UpdateAction "$(jq -n --arg id "$id" --argjson c "$cfg" '{id:$id, config:$c}')" >/dev/null
    info "Action $name updated."
  else
    kapi write/CreateAction "$(jq -n --arg n "$name" --argjson c "$cfg" '{name:$n, config:$c}')" >/dev/null
    info "Action $name created."
  fi
}

ensure_action segcore-silence-on  "$ACTION_ON"
ensure_action segcore-silence-off "$ACTION_OFF"

# Procedure: silence-on -> BatchPullRepo(segcore-*) -> silence-off. Stages run sequentially; each
# stage waits for its execution to finish before the next starts.
PROC_CFG="$(jq -n '{
  stages: [
    { name: "silence-on",  enabled: true, executions: [ { enabled: true, execution: { type: "RunAction",    params: { action: "segcore-silence-on" } } } ] },
    { name: "pull",        enabled: true, executions: [ { enabled: true, execution: { type: "BatchPullRepo", params: { pattern: "segcore-*" } } } ] },
    { name: "silence-off", enabled: true, executions: [ { enabled: true, execution: { type: "RunAction",    params: { action: "segcore-silence-off" } } } ] }
  ]
}')"

pid="$(find_id read/ListProcedures deploy-segcore)"
if [ -n "$pid" ]; then
  kapi write/UpdateProcedure "$(jq -n --arg id "$pid" --argjson c "$PROC_CFG" '{id:$id, config:$c}')" >/dev/null
  info "Procedure deploy-segcore updated."
else
  kapi write/CreateProcedure "$(jq -n --argjson c "$PROC_CFG" '{name:"deploy-segcore", config:$c}')" >/dev/null
  info "Procedure deploy-segcore created."
fi

info "Done. Deploy the fleet by running the 'deploy-segcore' Procedure (silences alerts for the rebuild)."
