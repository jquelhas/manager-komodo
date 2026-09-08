#!/usr/bin/env bash
# Build the security auditor's target list from Komodo. Writes security/state/targets.json and
# security/state/discovery.json. Idempotent and safe to run at any time.
#
# The fleet has no inventory file: Komodo's database is the source of truth. Servers give the name,
# mesh IP and reachability state; each host's PUBLIC_BIND_IP lives in its deploy Repo's
# `environment` (deliberately never in this repo's .env, so onboarding a host does not mean editing
# the manager). The manager's own entry comes from .env, not from Komodo.
#
# Two failure modes, handled differently and on purpose:
#   Komodo unreachable      -> keep the previous targets.json, ok=false. Scans then run against the
#                              last good list rather than against nothing.
#   Komodo answers with FEWER targets than before -> also keep the cache, and set shrunk=true.
#                              This is the dangerous case (a Server deleted, an API key demoted):
#                              silently shrinking coverage must be a human decision, never an
#                              accident. Delete targets.json to force acceptance.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/security-lib.sh"
cd "$SEC_REPO_DIR"
sec_load_env

APP_TAG="${APP_TAG:-$(env_get APP_TAG)}"; APP_TAG="${APP_TAG:-segcore}"
TARGETS_FILE="$(sec_state_path targets.json)"
IPV4_RE='^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'

sec_scan_begin discovery manager

fail_keep_cache() {   # $1 = why
  sec_warn "discovery degraded: $1"
  jq -n --argjson ts "$(date +%s)" --arg why "$1" \
        --argjson shrunk "${2:-false}" \
        --argjson count "$([ -s "$TARGETS_FILE" ] && jq '.targets|length' "$TARGETS_FILE" || echo 0)" \
     '{schema:1, ts:$ts, ok:false, shrunk:$shrunk, reason:$why, count:$count, incomplete:[]}' \
     | sec_state_write discovery.json
  sec_scan_end 0 0
  exit 0
}

servers="$(kapi read/ListServers 2>/dev/null || true)"
jq -e 'type == "array"' >/dev/null 2>&1 <<<"${servers:-null}" || fail_keep_cache "ListServers failed"

repos="$(kapi read/ListRepos 2>/dev/null || true)"
jq -e 'type == "array"' >/dev/null 2>&1 <<<"${repos:-null}" || fail_keep_cache "ListRepos failed"
stacks="$(kapi read/ListStacks 2>/dev/null || true)"
jq -e 'type == "array"' >/dev/null 2>&1 <<<"${stacks:-null}" || fail_keep_cache "ListStacks failed"

# server_id -> public_ip, from each deploy resource's environment. A host is deployed either as a
# Repo or as a Stack (the fleet is mid-migration; see the 2026-09-08 correction in docs/DESIGN.md),
# and both spell `server_id` and `environment` identically -- so only the endpoint differs. Reading
# only Repos would leave every migrated host with no role and no public IP, i.e. scanned against no
# baseline at all, and the loop below would not even warn: it iterates what the list contains.
# Also records why a host has no public IP, so a half-onboarded host is never mistaken for a clean
# one. A name present as both types is read once, as the Stack -- the migration target.
declare -A PUBIP=() ROLE=()
incomplete='[]'
while IFS=$'\t' read -r repo_name kind; do
  [ -n "$repo_name" ] || continue
  case "$kind" in
    repo)  arg=repo;  ep=read/GetRepo ;;
    stack) arg=stack; ep=read/GetStack ;;
    *) sec_warn "unknown deploy resource kind '$kind' for $repo_name"; continue ;;
  esac
  repo="$(kapi "$ep" "$(jq -nc --arg k "$arg" --arg r "$repo_name" '{($k):$r}')" 2>/dev/null || true)"
  jq -e 'type == "object"' >/dev/null 2>&1 <<<"${repo:-null}" || { sec_warn "$ep $repo_name failed"; continue; }
  sid="$(jq -r '.config.server_id // ""' <<<"$repo")"
  [ -n "$sid" ] || continue
  ROLE["$sid"]="$APP_TAG"
  ip="$(jq -r '.config.environment // ""' <<<"$repo" \
        | sed -n 's/^[[:space:]]*PUBLIC_BIND_IP[[:space:]]*=[[:space:]]*//p' | head -n1 \
        | sed -e 's/[[:space:]].*$//' -e 's/\r$//')"
  if [[ "$ip" =~ $IPV4_RE ]]; then
    PUBIP["$sid"]="$ip"
  else
    sec_warn "$kind $repo_name: PUBLIC_BIND_IP unusable ('${ip:-empty}')"
  fi
done < <( { jq -r --arg t "$APP_TAG" '.[] | select(.name | startswith($t + "-")) | .name + "\tstack"' <<<"$stacks"
            jq -r --arg t "$APP_TAG" '.[] | select(.name | startswith($t + "-")) | .name + "\trepo"'  <<<"$repos"; } \
          | awk -F'\t' '!seen[$1]++')

# Assemble. The manager is always the first target and is never discovered from Komodo.
targets="$(jq -n \
  --arg mip "$SECAUDIT_MANAGER_MESH_IP" --arg pip "$SECAUDIT_MANAGER_PUBLIC_IP" \
  '[{host:"manager", role:"manager", mesh_ip:$mip, public_ip:$pip, state:"Ok", scannable:1}]')"

while IFS=$'\t' read -r sid name state; do
  [ -n "$name" ] || continue
  mesh="$(jq -r --arg n "$name" '.[] | select(.name==$n) | (.info.address // .config.address // "")' <<<"$servers" \
          | grep -oE '100\.64\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1 || true)"
  role="${ROLE[$sid]:-unknown}"
  pub="${PUBIP[$sid]:-}"
  scannable=1; [ "$state" = "Ok" ] || scannable=0
  for f in mesh_ip:"$mesh" public_ip:"$pub" role:"$([ "$role" = unknown ] && echo "" || echo "$role")"; do
    [ -n "${f#*:}" ] || incomplete="$(jq -c --arg h "$name" --arg field "${f%%:*}" '. + [{host:$h, field:$field}]' <<<"$incomplete")"
  done
  targets="$(jq -c --arg h "$name" --arg r "$role" --arg m "$mesh" --arg p "$pub" \
                   --arg s "$state" --argjson sc "$scannable" \
             '. + [{host:$h, role:$r, mesh_ip:$m, public_ip:$p, state:$s, scannable:$sc}]' <<<"$targets")"
done < <(jq -r '.[] | [(.id // ._id["$oid"] // ""), .name, (.info.state // "")] | @tsv' <<<"$servers")

new_count="$(jq '.targets? // . | length' <<<"$(jq -n --argjson t "$targets" '{targets:$t}')")"
old_count=0
[ -s "$TARGETS_FILE" ] && old_count="$(jq '.targets | length' "$TARGETS_FILE" 2>/dev/null || echo 0)"

# Shrink guard: coverage may only shrink deliberately.
if [ "$old_count" -ge 2 ] && [ "$new_count" -lt "$(( (old_count * 6 + 9) / 10 ))" ]; then
  fail_keep_cache "target count dropped from $old_count to $new_count" true
fi

jq -n --argjson ts "$(date +%s)" --argjson t "$targets" \
  '{schema:1, generated_at:$ts, targets:$t}' | sec_state_write targets.json
jq -n --argjson ts "$(date +%s)" --argjson c "$new_count" --argjson inc "$incomplete" \
  '{schema:1, ts:$ts, ok:true, shrunk:false, reason:"", count:$c, incomplete:$inc}' \
  | sec_state_write discovery.json

sec_log "discovered $new_count targets ($(jq -r '[.[].host] | join(", ")' <<<"$targets"))"
sec_scan_end 1 "$new_count"
