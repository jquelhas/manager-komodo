#!/usr/bin/env bash
# Manage the app .env of every SEGCORE host from the manager, through Komodo.
#
# Komodo writes a Repo's `environment` to <path>/<env_file_path> (0600) on every Clone/Pull, right
# before running on_pull (./scripts/update.sh). So the per-host app .env becomes a managed resource:
# fleet-wide values live once as Komodo Variables (or in the Core config [secrets] block), per-host
# secrets live in that host's periphery.config.toml [secrets], and only the few non-sensitive
# per-host values are literal in the Repo's environment.
#
# This script is a SEEDER plus a LINTER, not a reconciler: the Komodo UI stays the source of truth
# for an environment once it is populated. It refuses to overwrite a non-empty environment unless
# --force is given.
#
# Usage (run on the MANAGER, as the operator):
#   scripts/setup-app-env.sh                     # dry run: lint + show what would change
#   scripts/setup-app-env.sh --apply             # push Variables and seed empty environments
#   scripts/setup-app-env.sh --apply --force     # also overwrite non-empty environments
#   scripts/setup-app-env.sh --apply --only segcore-demo
#   scripts/setup-app-env.sh --print segcore-demo   # render the .env for one host, to stdout
#   scripts/setup-app-env.sh --vars-only --apply    # push Variables, touch no Repo
#   scripts/setup-app-env.sh --guard-only --apply   # install the on_pull guard, keep environments
#
# Fleet-wide values come from the manager .env:
#   APPVAR_<NAME>=value      -> Komodo Variable <NAME>            (not a secret; value readable)
#   APPSECRET_<NAME>=value   -> Komodo Variable <NAME>, is_secret (hidden in logs / from non-admins)
#
# Per-host values are NOT configured here — that would mean editing this repo's .env for every new
# host. Non-sensitive ones (LOCAL_BASE_DOMAIN, or a legacy host's own COMPOSE_PROJECT_NAME) are
# edited in the Komodo UI on the Repo's Environment, after seeding; sensitive ones go in that host's
# /etc/komodo/periphery.config.toml [secrets]. The template ships them as CHANGE_ME and the on_pull
# guard refuses to deploy while a CHANGE_ME or an unresolved [[NAME]] is still in the written .env.
# Values that must never reach the manager database belong in the Core config [secrets] block or in
# the host's periphery.config.toml instead — this script only lints those, it never writes them.
#
# Env (from .env or the environment):
#   KOMODO_API_KEY, KOMODO_API_SECRET   required
#   KOMODO_URL                          default https://komodo.apps.internal
#   KOMODO_CACERT                       optional CA bundle for curl (--cacert)
#   KOMODO_INSECURE=1                   skip TLS verification (curl -k); not recommended
#   APP_TAG                             Repo name prefix to manage, default segcore

set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
info() { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_yel}[!]${c_rst} $*"; }
die()  { echo "${c_red}[x]${c_rst} $*" >&2; exit 1; }

command -v jq   >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

APPLY=0; FORCE=0; VARS_ONLY=0; GUARD_ONLY=0; ONLY=""; PRINT_ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply)      APPLY=1 ;;
    --force)      FORCE=1 ;;
    --vars-only)  VARS_ONLY=1 ;;
    --guard-only) GUARD_ONLY=1 ;;
    --only)      ONLY="${2:?--only needs a repo name}"; shift ;;
    --print)     PRINT_ONLY="${2:?--print needs a repo name}"; shift ;;
    -h|--help)   sed -n '2,36p' "$0"; exit 0 ;;
    *)           die "unknown argument: $1" ;;
  esac
  shift
done

TEMPLATE="$REPO_DIR/provisioning/app-env.template"
[ -f "$TEMPLATE" ] || die "missing $TEMPLATE"

# Read specific keys from .env. It is a docker-compose env file (KEY=value, values NOT shell-quoted
# and some contain spaces/&), so we must NOT source it as shell — we parse the exact keys we need.
env_get() {
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | head -n1 \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
# Same, but WITHOUT unquoting: for APPVAR_*/APPSECRET_* the surrounding quotes are part of the value.
# `update.sh` on the host sources the .env as shell, so a value like "M&Wnode&2000" needs to keep its
# quotes all the way through — stripping them here silently reintroduces the bug they exist to avoid.
env_get_raw() {
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=//p" .env | head -n1 | sed -e 's/\r$//'
}
KOMODO_API_KEY="${KOMODO_API_KEY:-$(env_get KOMODO_API_KEY)}"
KOMODO_API_SECRET="${KOMODO_API_SECRET:-$(env_get KOMODO_API_SECRET)}"
KOMODO_URL="${KOMODO_URL:-$(env_get KOMODO_URL)}"; KOMODO_URL="${KOMODO_URL:-https://komodo.apps.internal}"
APP_TAG="${APP_TAG:-segcore}"
: "${KOMODO_API_KEY:?KOMODO_API_KEY not set (.env)}"
: "${KOMODO_API_SECRET:?KOMODO_API_SECRET not set (.env)}"

# komodo.apps.internal is served with a step-ca cert the host does not trust by default.
: "${KOMODO_CACERT:=$REPO_DIR/docker/traefik/certs/step-ca-root.crt}"
CURL_OPTS=(-fsS --max-time 30)
if [ "${KOMODO_INSECURE:-0}" = "1" ]; then
  CURL_OPTS+=(-k)
elif [ -n "$KOMODO_CACERT" ] && [ -f "$KOMODO_CACERT" ]; then
  CURL_OPTS+=(--cacert "$KOMODO_CACERT")
fi

kapi() {
  curl "${CURL_OPTS[@]}" "$KOMODO_URL/$1" \
    -H "X-Api-Key: $KOMODO_API_KEY" -H "X-Api-Secret: $KOMODO_API_SECRET" \
    -H 'Content-Type: application/json' -d "$2"
}

kapi read/ListVariables '{}' >/dev/null \
  || die "cannot reach the Komodo API at $KOMODO_URL (check KOMODO_URL / creds / step-ca trust)"

# ---------------------------------------------------------------------------
# 1. Fleet-wide Variables, from APPVAR_* / APPSECRET_* in the manager .env
# ---------------------------------------------------------------------------
# Names only; values are fetched individually so they never land in a shell array that could be
# echoed by an accidental `set -x`.
appvar_names() { sed -n 's/^[[:space:]]*APPVAR_\([A-Za-z_][A-Za-z0-9_]*\)[[:space:]]*=.*/\1/p' .env 2>/dev/null; }
appsecret_names() { sed -n 's/^[[:space:]]*APPSECRET_\([A-Za-z_][A-Za-z0-9_]*\)[[:space:]]*=.*/\1/p' .env 2>/dev/null; }

EXISTING_VARS="$(kapi read/ListVariables '{}' | jq -r '.[].name')"
# name -> value, for the shell-safety lint below. Needs admin (secret values are only served to
# admins); values stay inside this variable and are never echoed.
VAR_VALUES="$(kapi read/ListVariables '{}' | jq -c 'map({(.name): .value}) | add // {}')"
# Keys of the Core config [secrets] block: queryable by name, values never served by the API.
CORE_SECRETS="$(kapi read/ListSecrets '{}' | jq -r '.[]? // empty')"

ensure_variable() {
  local name="$1" secret="$2" value
  value="$(env_get_raw "$3")"
  [ -n "$value" ] || { warn "Variable $name skipped: $3 is empty in .env"; return 0; }
  if grep -qxF "$name" <<<"$EXISTING_VARS"; then
    if [ "$APPLY" = 1 ]; then
      kapi write/UpdateVariableValue "$(jq -n --arg n "$name" --arg v "$value" '{name:$n, value:$v}')" >/dev/null
      kapi write/UpdateVariableIsSecret "$(jq -n --arg n "$name" --argjson s "$secret" '{name:$n, is_secret:$s}')" >/dev/null
      info "Variable $name updated (is_secret=$secret)."
    else
      echo "    would update Variable $name (is_secret=$secret)"
    fi
  else
    if [ "$APPLY" = 1 ]; then
      kapi write/CreateVariable "$(jq -n --arg n "$name" --arg v "$value" --argjson s "$secret" \
        '{name:$n, value:$v, description:"Managed by scripts/setup-app-env.sh", is_secret:$s}')" >/dev/null
      info "Variable $name created (is_secret=$secret)."
    else
      echo "    would create Variable $name (is_secret=$secret)"
    fi
    EXISTING_VARS="$EXISTING_VARS"$'\n'"$name"
  fi
}

if [ -z "$PRINT_ONLY" ]; then
  echo "== Fleet-wide Variables (from APPVAR_* / APPSECRET_* in .env)"
  while read -r n; do [ -n "$n" ] && ensure_variable "$n" false "APPVAR_$n"; done <<<"$(appvar_names)"
  while read -r n; do [ -n "$n" ] && ensure_variable "$n" true  "APPSECRET_$n"; done <<<"$(appsecret_names)"
fi
[ "$VARS_ONLY" = 1 ] && { info "Done (--vars-only)."; exit 0; }

# ---------------------------------------------------------------------------
# 2. Render the template for one host
# ---------------------------------------------------------------------------
# Only MESH_IP and HOSTNAME are derivable. Anything else per-host stays CHANGE_ME by design, and
# blocks --apply until the operator fills it in.
render() {
  local mesh_ip="$1" hostname="$2" upper
  # {{HOST_UPPER}} feeds the per-host Variable names, e.g. [[DEMO_JWT_SECRET]]. Kept identical to
  # host_upper() in provisioning/server.py, which names them at onboarding.
  upper="$(tr '[:lower:]' '[:upper:]' <<<"$hostname" | sed 's/[^A-Z0-9_]/_/g')"
  sed -e "s|{{MESH_IP}}|$mesh_ip|g" -e "s|{{HOSTNAME}}|$hostname|g" -e "s|{{HOST_UPPER}}|$upper|g" "$TEMPLATE"
}

# Every [[NAME]] must resolve at deploy time, or Komodo writes it through literally (it does not
# fail): svi::interpolate_variables is called with fail_on_missing_variable=false. Core-side names we
# can check here; the per-host ones can only be checked on the host, so they are listed explicitly.
# Names expected to come from a host's periphery.config.toml [secrets] rather than from Core. Empty
# by default: as of 2026-08-20 every secret is a fleet-wide Variable. Add a name here when you move
# it to per-host — and remember to delete the global Variable, or Core keeps winning.
PERIPHERY_SECRETS="${PERIPHERY_SECRETS:-}"

# Last line of defence, on the host itself: refuse to deploy an .env that still carries a
# placeholder, or whose TENANT_CONFIG_KEY is empty (at-rest encryption would silently fall back to
# JWT_SECRET). Two constraints on how this string is written, both learned the hard way:
#   no literal "[[" — Komodo interpolates on_pull too and reads it as an unclosed placeholder.
#                     Matching the closing "]]" catches the same thing.
#   no backslashes  — the TOML export writes it in a """...""" string without escaping them,
#                     which makes read/ExportAllResourcesToToml emit invalid TOML.
# Keep in sync with APP_ON_PULL in docker-compose.yml.
ON_PULL_GUARD="if grep -qF -e ']]' -e 'CHANGE_ME' .env; then echo 'ERROR: unresolved placeholder in .env - refusing to deploy'; grep -nF -e ']]' -e 'CHANGE_ME' .env | cut -d= -f1; exit 1; fi; if grep -qx 'TENANT_CONFIG_KEY=' .env; then echo 'ERROR: TENANT_CONFIG_KEY is empty - refusing to deploy (at-rest encryption would silently fall back to JWT_SECRET)'; exit 1; fi; ./scripts/update.sh"

lint() {
  local rendered="$1" host="$2" rc=0 name assignments
  # Only the KEY=value lines matter. The template's own header documents the [[NAME]] and CHANGE_ME
  # conventions, so linting the comments too would flag the documentation as a broken reference.
  assignments="$(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' <<<"$rendered" || true)"
  while read -r name; do
    [ -n "$name" ] || continue
    if grep -qxF "$name" <<<"$EXISTING_VARS" || grep -qxF "$name" <<<"$CORE_SECRETS"; then continue; fi
    if grep -qw -- "$name" <<<"$PERIPHERY_SECRETS"; then
      echo "    [[${name}]] -> expected in $host:/etc/komodo/periphery.config.toml [secrets]"
      continue
    fi
    echo "${c_red}    [[${name}]] resolves nowhere${c_rst} — would be written literally into .env"
    rc=1
  done <<<"$(grep -o '\[\[[A-Za-z_][A-Za-z0-9_]*\]\]' <<<"$assignments" | tr -d '[]' | sort -u)"
  # CHANGE_ME is expected on a fresh seed: per-host values are filled in afterwards in the Komodo UI,
  # not here. So it is a warning, not a failure — the on_pull guard is what stops a deploy while one
  # is still there.
  # `update.sh` on the host SOURCES the .env as a shell script, so a value with an unquoted shell
  # metacharacter breaks the deploy — `DEFAULT_ADMIN_PASSWORD=M&Wnode&2000` became "Wnode: command
  # not found" on 2026-08-21. Docker Compose strips surrounding quotes on interpolation, so quoting
  # keeps both consumers happy. Resolve the [[NAME]]s first: the hazard is usually in a secret's
  # value, not in the template text.
  local key val ref repl
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="${line%%=*}"; val="${line#*=}"
    # Same two rules Komodo applies when it parses the environment, so the check sees what the host
    # will actually get: a whitespace-preceded # is an inline comment, and trailing space is trimmed.
    val="$(sed -e 's/[[:space:]]\+#.*$//' -e 's/[[:space:]]*$//' <<<"$val")"
    # Iterate the finite list of names in this line — a re-matching while-loop can fail to converge.
    for ref in $(grep -oE '\[\[[A-Za-z_][A-Za-z0-9_]*\]\]' <<<"$val" | tr -d '[]' | sort -u); do
      repl="$(jq -r --arg n "$ref" '.[$n] // ""' <<<"$VAR_VALUES")"
      # The replacement MUST be quoted: since bash 5.2 an unquoted & in it expands to the matched
      # text, so a password like M&Wnode&2000 would silently corrupt itself here.
      val="${val//"[[$ref]]"/"$repl"}"
    done
    case "$val" in '"'*'"') continue ;; esac          # already quoted -> safe to source
    case "$val" in *[\&\|\;\<\>\(\)\`\ ]*)
      echo "${c_red}    $key has an unquoted shell metacharacter${c_rst} — update.sh sources the .env; wrap the value in double quotes"
      rc=1 ;;
    esac
  done <<<"$assignments"

  if grep -q 'CHANGE_ME' <<<"$assignments"; then
    echo "${c_yel}    CHANGE_ME to fill in the Komodo UI${c_rst} (Repos -> $repo_name -> Environment):"
    grep -n 'CHANGE_ME' <<<"$assignments" | sed 's/^/      /'
  fi
  return $rc
}

# ---------------------------------------------------------------------------
# 3. Seed the Repo environments
# ---------------------------------------------------------------------------
SERVERS="$(kapi read/ListServers '{}')"
REPOS="$(kapi read/ListRepos '{}')"

# The Server address is https://<mesh-ip>:8120 — the same source the Prometheus http_sd in
# provisioning/server.py derives its targets from.
mesh_ip_of() {
  jq -r --arg id "$1" '.[] | select(.id==$id) | .info.address // ""' <<<"$SERVERS" \
    | grep -oE '100\.64\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1
}

rc=0
while read -r repo_name; do
  [ -n "$repo_name" ] || continue
  case "$repo_name" in "$APP_TAG"-*) ;; *) continue ;; esac
  [ -n "$ONLY" ] && [ "$ONLY" != "$repo_name" ] && continue
  [ -n "$PRINT_ONLY" ] && [ "$PRINT_ONLY" != "$repo_name" ] && continue

  cfg="$(kapi read/GetRepo "$(jq -n --arg r "$repo_name" '{repo:$r}')")"
  server_id="$(jq -r '.config.server_id' <<<"$cfg")"
  current="$(jq -r '.config.environment // ""' <<<"$cfg")"
  mesh_ip="$(mesh_ip_of "$server_id")"
  host="${repo_name#"$APP_TAG"-}"
  [ -n "$mesh_ip" ] || { warn "$repo_name: no mesh IP on its Server — skipped"; rc=1; continue; }

  rendered="$(render "$mesh_ip" "$host")"

  if [ -n "$PRINT_ONLY" ]; then printf '%s\n' "$rendered"; exit 0; fi

  echo
  echo "== $repo_name (host $host, mesh $mesh_ip)"
  # Lint what will ACTUALLY be written: once an environment is populated it is hand-edited in the UI,
  # so linting only the template would miss exactly the problems the UI can introduce.
  LINT_TARGET="template"; [ -n "$current" ] && LINT_TARGET="environment in Komodo"

  # Install just the on_pull guard, leaving `environment` alone. For environments written by hand in
  # the UI: --force would overwrite them, and they still need the guard.
  if [ "$GUARD_ONLY" = 1 ]; then
    if [ "$APPLY" != 1 ]; then
      echo "    would set the on_pull guard (environment untouched)"
    else
      kapi write/UpdateRepo "$(jq -n --arg id "$repo_name" --arg g "$ON_PULL_GUARD" \
        '{id:$id, config:{on_pull:{path:"", command:$g, shell_mode:true}}}')" >/dev/null
      info "on_pull guard set (environment untouched)."
    fi
    continue
  fi
  echo "    linting the $LINT_TARGET"
  if [ -n "$current" ]; then lint "$current" "$host" || rc=1; else lint "$rendered" "$host" || rc=1; fi

  if [ -n "$current" ] && [ "$FORCE" != 1 ]; then
    if [ "$current" = "$rendered" ]; then
      info "environment already matches the template."
    else
      warn "environment is already populated — left untouched (the UI is the source of truth)."
      echo "    re-seed from the template with --force, or edit it in the Komodo UI."
    fi
    continue
  fi

  if [ "$APPLY" != 1 ]; then
    echo "    would write ${#rendered} bytes to environment (env_file_path=.env)"
    continue
  fi
  [ $rc = 0 ] || die "refusing to --apply while the lint above fails"

  kapi write/UpdateRepo "$(jq -n --arg id "$repo_name" --arg e "$rendered" --arg g "$ON_PULL_GUARD" \
    '{id:$id, config:{environment:$e, env_file_path:".env", skip_secret_interp:false,
                      on_pull:{path:"", command:$g, shell_mode:true}}}')" >/dev/null
  info "environment written (+ on_pull guard)."
done <<<"$(jq -r '.[].name' <<<"$REPOS")"

echo
if [ "$APPLY" != 1 ]; then
  info "Dry run. Nothing was changed. Re-run with --apply."
else
  info "Done. The next Pull of each Repo writes /opt/SEGCORE/.env (0600) before update.sh runs."
fi
exit $rc
