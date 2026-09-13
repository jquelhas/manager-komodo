#!/usr/bin/env bash
# Report, in the Komodo UI, whether each app host's checkout is behind the app repo.
#
# WHY THIS EXISTS. The app Stacks run with `files_on_host = true`, which is a deliberate choice
# (see the 2026-09-08 correction in docs/DESIGN.md). The cost of that choice is that Komodo never
# looks at git: `RefreshStackCache` sets the hash fields back to None for a files-on-host Stack
# (bin/core/src/api/write/stack.rs, "Files on host can set hash / message back to None"), so the
# `deployed: <hash>` badge the Stack page would otherwise draw is simply not rendered. There is no
# setting that turns it on — only a repo-based Stack gets it, and we do not want one.
#
# So the signal is rebuilt from two halves that Komodo already moves for us:
#
#   the HOST half   the Stack's `config_files` track `.git/HEAD` and `.git/refs/heads/<branch>`.
#                   Those are ordinary files under `run_directory`, and periphery reads whatever
#                   path it is given (bin/periphery/src/api/compose.rs, no whitelist), so the
#                   host's current commit arrives in `info.remote_contents` on every cache
#                   refresh -- every `resource_poll_interval`, 5 minutes by default. No agent on
#                   the host, no SSH, no new port. A bare-string `config_files` entry defaults to
#                   `StackFileRequires::None`, so tracking them changes no deploy decision.
#
#   the REMOTE half this script asks GitHub where the branch actually is.
#
# The verdict goes back into Komodo as the Stack's description (first line, which is what the
# resource header shows) and as a `git-behind` tag (which is a column in the Stacks table). That
# is the whole point: the answer shows up where you are already looking.
#
# Usage (on the MANAGER, as the operator, or from manager-app-git-status.timer):
#   scripts/app-git-status.sh                  check every host and write the verdicts
#   scripts/app-git-status.sh --dry-run        print what it would write, touch nothing
#   scripts/app-git-status.sh --only segcore-demo
#
# Env (from .env or the environment):
#   KOMODO_API_KEY, KOMODO_API_SECRET     required
#   KOMODO_URL                            default https://komodo.apps.internal
#   KOMODO_CACERT                         CA bundle for curl; defaults to the step-ca root in-tree
#   KOMODO_INSECURE=1                     skip TLS verification (curl -k); not recommended
#   APP_GIT_STATUS_TOKEN                  required; GitHub PAT, READ-ONLY, see .env.example
#   APP_GIT_REPO                          default jquelhas/GIMSv2
#   APP_GIT_BRANCH                        default main
#   APP_TAG                               Stack name prefix to check, default segcore
#
# Exit code is about THIS SCRIPT, not about the fleet: 0 when every host was checked, non-zero
# when something stopped it from checking. "A host is 12 commits behind" is a normal, successful
# run -- the finding belongs in the UI, not in an exit code, or the timer would mail about a
# state that is often perfectly intentional.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
info() { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_yel}[!]${c_rst} $*"; }
die()  { echo "${c_red}[x]${c_rst} $*" >&2; exit 1; }

command -v jq   >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

DRY_RUN=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --only)    ONLY="${2:?--only needs a stack name}"; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *)         die "unknown argument: $1" ;;
  esac
  shift
done

# .env is a docker-compose env file (KEY=value, unquoted values that may contain spaces and &), so
# it must NOT be sourced as shell -- parse the exact keys we need. Same helper as setup-app-env.sh.
env_get() {
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | head -n1 \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
KOMODO_API_KEY="${KOMODO_API_KEY:-$(env_get KOMODO_API_KEY)}"
KOMODO_API_SECRET="${KOMODO_API_SECRET:-$(env_get KOMODO_API_SECRET)}"
KOMODO_URL="${KOMODO_URL:-$(env_get KOMODO_URL)}"; KOMODO_URL="${KOMODO_URL:-https://komodo.apps.internal}"
APP_GIT_STATUS_TOKEN="${APP_GIT_STATUS_TOKEN:-$(env_get APP_GIT_STATUS_TOKEN)}"
APP_GIT_REPO="${APP_GIT_REPO:-$(env_get APP_GIT_REPO)}";     APP_GIT_REPO="${APP_GIT_REPO:-jquelhas/GIMSv2}"
APP_GIT_BRANCH="${APP_GIT_BRANCH:-$(env_get APP_GIT_BRANCH)}"; APP_GIT_BRANCH="${APP_GIT_BRANCH:-main}"
APP_TAG="${APP_TAG:-segcore}"
: "${KOMODO_API_KEY:?KOMODO_API_KEY not set (.env)}"
: "${KOMODO_API_SECRET:?KOMODO_API_SECRET not set (.env)}"

# Deliberately NOT read from the Komodo git provider account, even though Core holds a usable PAT
# there and read/ListGitProviderAccounts hands it over in clear to an admin key. That token can
# write; this job only ever reads one ref. A separate, read-only, single-repo token means a leak
# here cannot push to the app repo, and it can be rotated without touching any deploy.
[ -n "$APP_GIT_STATUS_TOKEN" ] || die "APP_GIT_STATUS_TOKEN not set (.env) -- see .env.example for the exact token to create"

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

kapi read/ListStacks '{}' >/dev/null \
  || die "cannot reach the Komodo API at $KOMODO_URL (check KOMODO_URL / creds / step-ca trust)"

# GitHub compare. Prints "<http_code>\n<body>" — the code travels in stdout rather than in a
# variable because every caller wraps this in $( ), which is a subshell: a global assigned in here
# never reaches the caller, and the status silently reads as empty.
# The code has to survive at all because 404 is meaningful (the host sits on a commit GitHub has
# never seen) and must not be conflated with "GitHub is unreachable". 000 means curl itself failed.
gh_compare() {
  local base="$1" head="$2" out
  out="$(curl -sS --max-time 30 -w $'\n%{http_code}' \
    -H "Authorization: Bearer $APP_GIT_STATUS_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/$APP_GIT_REPO/compare/$base...$head" 2>/dev/null)" \
    || { printf '000\n'; return 0; }
  printf '%s\n%s' "${out##*$'\n'}" "${out%$'\n'*}"
}

# The description line this script owns. Everything the operator wrote stays underneath it: on the
# first run an existing hand-written description is pushed down to line 2 rather than replaced,
# and from then on only the marked line is rewritten. The Komodo resource header renders
# description.split("\n")[0] (ui/src/resources/description.tsx), so the verdict is what you see.
MARK="[git]"

compose_description() {
  local verdict="$1" current="$2" rest
  rest="$(printf '%s' "$current" | awk -v m="$MARK" 'NR==1 && index($0, m)==1 {next} {print}')"
  if [ -n "$rest" ]; then printf '%s\n%s' "$verdict" "$rest"; else printf '%s' "$verdict"; fi
}

STACKS="$(kapi read/ListStacks '{}')"
TARGETS="$(jq -r --arg t "$APP_TAG" '.[].name | select(startswith($t + "-"))' <<<"$STACKS" | sort)"
[ -n "$TARGETS" ] || die "no Stack named $APP_TAG-* -- nothing to check"

STATE_FILE="$REPO_DIR/var/app-git-status.json"
state='{}'
rc=0
checked=0; behind=0

while read -r stack; do
  [ -n "$stack" ] || continue
  [ -n "$ONLY" ] && [ "$ONLY" != "$stack" ] && continue

  cfg="$(kapi read/GetStack "$(jq -nc --arg s "$stack" '{stack:$s}')")"

  # `.git/HEAD` says which branch is checked out; the ref file holds that branch's commit. Both
  # are read straight off the host by the periphery on every cache refresh.
  head_ref="$(jq -r '.info.remote_contents[]? | select(.path==".git/HEAD") | .contents' <<<"$cfg" | tr -d '\n')"
  host_branch="${head_ref#ref: refs/heads/}"
  ref_path=".git/refs/heads/$APP_GIT_BRANCH"
  host_sha="$(jq -r --arg p "$ref_path" '.info.remote_contents[]? | select(.path==$p) | .contents' <<<"$cfg" | tr -d '[:space:]')"
  ref_error="$(jq -r --arg p "$ref_path" '.info.remote_errors[]? | select(.path==$p) | "yes"' <<<"$cfg" | head -n1)"

  status=""; verdict=""; tag_behind=0

  if [ -z "$head_ref" ] && [ -z "$host_sha" ]; then
    # Neither file came back: the Stack is not tracking them, or the host is unreachable.
    status="untracked"
    verdict="$MARK sem dados de git — o host não devolveu .git/HEAD (config_files em falta, ou host inacessível)"
  elif [ "$host_branch" = "$head_ref" ]; then
    # The prefix did not strip, so HEAD is detached (a raw sha) rather than on a branch.
    status="detached"
    verdict="$MARK HEAD destacado no host (${head_ref:0:12}) — não está num branch"
  elif [ "$host_branch" != "$APP_GIT_BRANCH" ]; then
    status="wrong_branch"
    verdict="$MARK o host está no branch '$host_branch', não em '$APP_GIT_BRANCH'"
  elif [ -n "$ref_error" ] || [ -z "$host_sha" ]; then
    # Self-healing: `git gc` / `git pack-refs` moves the loose ref into .git/packed-refs, and the
    # next pull writes it loose again. Every deploy pulls, so this clears itself at the next one.
    status="ref_unreadable"
    verdict="$MARK não consegui ler $ref_path no host (ref empacotado? resolve-se no próximo deploy)"
  else
    gh_out="$(gh_compare "$host_sha" "$APP_GIT_BRANCH")"
    gh_code="${gh_out%%$'\n'*}"
    body="${gh_out#*$'\n'}"
    if [ "$gh_code" = "200" ]; then
      gh_status="$(jq -r '.status' <<<"$body")"
      n_behind="$(jq -r '.behind_by' <<<"$body")"
      n_ahead="$(jq -r '.ahead_by' <<<"$body")"
      # In `compare/BASE...HEAD` with BASE=host and HEAD=branch tip, commits the host is missing
      # come back as `ahead_by` -- the branch is ahead OF THE HOST. Reading `behind_by` here is the
      # easy mistake: that field counts commits the host has and the branch does not.
      tip_sha="$(jq -r '.commits[-1].sha // ""' <<<"$body")"
      tip_date="$(jq -r '.commits[-1].commit.author.date // ""' <<<"$body" | cut -dT -f1)"
      case "$gh_status" in
        identical)
          status="current"
          verdict="$MARK actualizado — $APP_GIT_BRANCH ${host_sha:0:7}" ;;
        ahead)
          status="behind"; tag_behind=1
          verdict="$MARK $n_ahead commit(s) atrás — ${host_sha:0:7} → ${tip_sha:0:7} ($tip_date)" ;;
        behind)
          # The host carries commits the branch does not: someone committed on the host.
          status="local_commits"
          verdict="$MARK o host tem $n_behind commit(s) que não estão em $APP_GIT_BRANCH" ;;
        *)
          status="diverged"; tag_behind=1
          verdict="$MARK divergente — $n_ahead à frente no remoto, $n_behind só no host" ;;
      esac
    elif [ "$gh_code" = "404" ]; then
      status="unknown_commit"
      verdict="$MARK o commit do host (${host_sha:0:7}) não existe em $APP_GIT_REPO"
    else
      status="github_error"
      verdict="$MARK não consegui perguntar ao GitHub (HTTP $gh_code)"
      rc=1
    fi
  fi

  checked=$((checked + 1))
  [ "$tag_behind" = 1 ] && behind=$((behind + 1))

  case "$status" in
    current)                echo "    ${c_grn}$stack${c_rst}: $verdict" ;;
    behind|diverged)        echo "    ${c_yel}$stack${c_rst}: $verdict" ;;
    *)                      echo "    ${c_red}$stack${c_rst}: $verdict" ;;
  esac

  state="$(jq -c --arg s "$stack" --arg st "$status" --arg sha "$host_sha" --arg b "$host_branch" \
    --argjson ts "$(date +%s)" \
    '. + {($s): {status:$st, sha:$sha, branch:$b, ts:$ts}}' <<<"$state")"

  [ "$DRY_RUN" = 1 ] && continue

  # Tags are replaced wholesale by UpdateResourceMeta, so send the existing ones back plus/minus
  # ours. Names are accepted and created on demand (bin/core/src/resource/mod.rs, update_meta).
  # Tag documents carry their id as `_id.$oid`, NOT as `id` -- a `select(.id == ...)` here matches
  # nothing and would silently strip every existing tag off the resource.
  tag_names="$(jq -r --argjson all "$(kapi read/ListTags '{}')" \
    '($all | map({key: ._id["$oid"], value: .name}) | from_entries) as $m
     | .tags[]? | $m[.] // empty' <<<"$cfg" 2>/dev/null || true)"
  new_tags="$(printf '%s\n' "$tag_names" | grep -v '^git-behind$' | grep -v '^$' || true)"
  [ "$tag_behind" = 1 ] && new_tags="$(printf '%s\ngit-behind' "$new_tags")"
  tags_json="$(printf '%s\n' "$new_tags" | grep -v '^$' | jq -R . | jq -sc .)"

  current_desc="$(jq -r '.description // ""' <<<"$cfg")"
  new_desc="$(compose_description "$verdict" "$current_desc")"

  kapi write/UpdateResourceMeta "$(jq -nc --arg s "$stack" --arg d "$new_desc" --argjson t "$tags_json" \
    '{target:{type:"Stack", id:$s}, description:$d, tags:$t}')" >/dev/null \
    || { warn "$stack: failed to write the verdict back to Komodo"; rc=1; }
done <<<"$TARGETS"

mkdir -p "$(dirname "$STATE_FILE")"
jq -n --argjson ts "$(date +%s)" --argjson h "$state" '{schema:1, ts:$ts, stacks:$h}' > "$STATE_FILE"

echo
if [ "$DRY_RUN" = 1 ]; then
  info "Dry run. $checked host(s) checked, nothing written to Komodo."
else
  info "$checked host(s) checked, $behind behind. Verdicts written to the Stack description + tag."
fi
exit $rc
