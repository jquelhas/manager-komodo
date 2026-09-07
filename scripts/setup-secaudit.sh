#!/usr/bin/env bash
# Install (idempotent) the two zero-privilege courier Deployments per Komodo server, which are the
# ONLY way the manager talks to the host bundle. Run on the MANAGER, like setup-deploy-procedure.sh.
#
#   secaudit-collect-<server>   `cat` of /var/lib/secaudit/report.ndjson, harvested from the
#                               container log. Mount is :ro — the manager can read the audit, never
#                               alter it.
#   secaudit-trigger-<server>   `touch` of a sentinel in a write-only subdirectory, which the host's
#                               secaudit-host.path unit turns into an out-of-band audit run. The
#                               worst an abuse of this achieves is asking for an audit.
#
# Neither container has a network, capabilities, docker.sock or a listening port, and neither needs
# a Headscale ACL change: the transport is Core -> periphery :8120, which is already open.
#
# Usage:  scripts/setup-secaudit.sh [--dry-run] [--destroy]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/security-lib.sh"
cd "$SEC_REPO_DIR"
sec_load_env

command -v jq >/dev/null || sec_die "jq is required"

# Pinned by digest, not by tag: this image runs on production application hosts, and a digest
# cannot be moved under us. alpine 3.24.
COURIER_IMAGE="alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

DRY=0; DESTROY=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --destroy) DESTROY=1 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sec_die "unknown argument: $a" ;;
  esac
done

servers="$(kapi read/ListServers)"
jq -e 'type == "array"' >/dev/null <<<"$servers" || sec_die "ListServers failed"

# --- destroy -----------------------------------------------------------------------------------
if [ "$DESTROY" = 1 ]; then
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    case "$name" in
      secaudit-collect-*|secaudit-trigger-*) ;;
      *) continue ;;
    esac
    if [ "$DRY" = 1 ]; then echo "would destroy+delete $name"; continue; fi
    sec_log "destroying $name"
    kapi execute/DestroyDeployment "$(jq -nc --arg d "$name" '{deployment:$d}')" >/dev/null 2>&1 || true
    kapi write/DeleteDeployment "$(jq -nc --arg i "$name" '{id:$i}')" >/dev/null 2>&1 || true
  done < <(kapi read/ListDeployments | jq -r '.[].name')
  sec_log "done. The host bundle itself is removed on each host with install-secaudit.sh --uninstall"
  exit 0
fi

# --- the one destructive primitive in this design, and its guard --------------------------------
# execute/Deploy removes and recreates the container WITH THAT NAME. If a courier were ever created
# with a name that collides with a real container, deploying it would delete that container. So we
# refuse to create a Deployment whose name already exists as a container we did not make. This is
# an assertion in code, not a note in a document, because it is the only path by which this system
# could destroy anything.
assert_no_collision() {   # $1 = server name, $2 = deployment name
  local conts
  conts="$(kapi read/ListDockerContainers "$(jq -nc --arg s "$1" '{server:$s}')" 2>/dev/null || echo '[]')"
  jq -e 'type == "array"' >/dev/null <<<"$conts" || { sec_warn "cannot list containers on $1 — skipping collision check"; return 0; }
  if jq -e --arg n "$2" 'any(.[]; .name == $n)' >/dev/null <<<"$conts"; then
    # Ours are recreated by every Deploy, so an existing one is expected once installed.
    if kapi read/ListDeployments | jq -e --arg n "$2" 'any(.[]; .name == $n)' >/dev/null; then
      return 0
    fi
    sec_die "a container named '$2' already exists on $1 and is NOT one of ours. Refusing: deploying would delete it."
  fi
}

# One `secaudit` tag on all four couriers, so the UI can filter them as a group and they are not
# scattered among the application's own deployments. Deliberately NOT the `segcore` tag: a
# tag-based BatchDeploy or BatchPullRepo over `segcore` would then sweep the auditors up with the
# app, which is how a routine fleet operation ends up triggering audits on every host at once.
ensure_tag() {
  local id
  id="$(kapi read/ListTags '{}' 2>/dev/null | jq -r '.[]? | select(.name=="secaudit") | .id // ._id["$oid"]' | head -1)"
  if [ -z "$id" ]; then
    kapi write/CreateTag '{"name":"secaudit"}' >/dev/null 2>&1 || true
    id="$(kapi read/ListTags '{}' 2>/dev/null | jq -r '.[]? | select(.name=="secaudit") | .id // ._id["$oid"]' | head -1)"
  fi
  [ -n "$id" ] || { sec_warn "could not resolve the secaudit tag (cosmetic; carrying on)"; return 0; }
  printf '%s' "$id"
}
TAG_ID="$(ensure_tag)"

tag_it() {   # $1 = deployment name
  [ -n "$TAG_ID" ] || return 0
  kapi write/UpdateResourceMeta \
    "$(jq -nc --arg n "$1" --arg t "$TAG_ID" '{target:{type:"Deployment", id:$n}, tags:[$t]}')" \
    >/dev/null 2>&1 || sec_warn "  could not tag $1 (cosmetic; carrying on)"
}

# Description and tag, set through the API so the UI explains itself. This is the whole "put the
# on-demand audit in the Komodo UI" story: a Deployment already appears on its server's page, and
# clicking Deploy on the trigger IS the on-demand audit. What was missing was any indication of
# that to somebody who did not build it. Operator-facing text is in Portuguese, matching the
# Grafana dashboards; the code around it stays English.
describe() {   # $1 = deployment name, $2 = description
  kapi write/UpdateResourceMeta \
    "$(jq -nc --arg n "$1" --arg d "$2" '{target:{type:"Deployment", id:$n}, description:$d}')" \
    >/dev/null 2>&1 || sec_warn "  could not set the description on $1 (cosmetic; carrying on)"
}

# The UI shows START and REDEPLOY on an exited one-shot, never "Deploy" — say the real button
# names. Both work for the trigger; Start is lighter because it reuses the container instead of
# recreating it. Verified 2026-09-07.
DESC_TRIGGER='AUDITORIA DE SEGURANCA A PEDIDO. Carregue em START (ou Redeploy) para auditar este host agora - leva 5-10 min: lynis, CIS Docker, CVEs das imagens e portas a escuta. NAO altera nada no host, so le. O resultado aparece no Grafana, pasta "security", depois de o manager o recolher (timer diario, ou ja: scripts/secaudit.sh audit <host>). Este container so faz um touch num ficheiro: sem rede, sem privilegios, sem docker.sock.'
DESC_COLLECT='Le o ultimo relatorio de auditoria deste host e devolve-o ao manager pelo log. Nao precisa de o usar: o manager recolhe por timer. START ou Redeploy releem agora. So faz cat de um ficheiro montado read-only; sem rede e sem privilegios.'

courier_config() {   # $1 = server_id, $2 = role (collect|trigger)
  local sid="$1" role="$2" vol cmd entry
  if [ "$role" = collect ]; then
    vol="/var/lib/secaudit:/r:ro"; cmd="/r/report.ndjson"; entry="/bin/cat"
  else
    vol="/var/lib/secaudit/trigger.d:/t"; cmd="/t/run"; entry="/bin/touch"
  fi
  jq -nc \
    --arg sid "$sid" --arg img "$COURIER_IMAGE" --arg vol "$vol" --arg cmd "$cmd" \
    --arg entry "$entry" --arg role "$role" \
  '{
     server_id: $sid,
     image: {type: "Image", params: {image: $img}},
     # network MUST be set: the Komodo schema defaults it to "host", so omitting it would hand a
     # courier the host network namespace for no reason whatsoever.
     network: "none",
     volumes: $vol,
     command: $cmd,
     extra_args: ["--entrypoint", $entry,
                  "--cap-drop", "ALL", "--read-only",
                  "--security-opt", "no-new-privileges",
                  "--memory", "32m", "--pids-limit", "16",
                  "--log-opt", "max-size=8m", "--log-opt", "max-file=2"],
     ports: "",
     restart: "no",
     # A courier exits on purpose every single day. Without this, Komodo would e-mail a
     # ContainerStateChange alert for each exit, on every host.
     send_alerts: false,
     # This Komodo has a "Global Auto Update" Procedure. An auto-updating courier would be
     # redeployed out of band, destroying a log before it was harvested. Also pointless: the image
     # is pinned by digest, which never moves.
     poll_for_updates: false,
     auto_update: false,
     redeploy_on_build: false,
     skip_secret_interp: true,
     labels: ("secaudit=1\nsecaudit.role=" + $role)
   }'
}

# After every create/update, read the resource back and assert the fields survived the round trip
# through the API, the database and Komodo's interpolator. docs/DESIGN.md:807-821 records three
# separate failures of exactly this kind; a comment is not a check.
echo_check() {   # $1 = deployment name, $2 = expected config json
  local got want
  got="$(kapi read/GetDeployment "$(jq -nc --arg d "$1" '{deployment:$d}')")"
  for field in network command volumes; do
    want="$(jq -r --arg f "$field" '.[$f]' <<<"$2")"
    got_v="$(jq -r --arg f "$field" '.config[$f]' <<<"$got")"
    [ "$want" = "$got_v" ] || sec_die "echo-check failed on $1.$field: sent '$want', got '$got_v'"
  done
  [ "$(jq -r '.config.network' <<<"$got")" = "none" ] || sec_die "$1: network is not 'none'"
  [ "$(jq -r '.config.image.params.image' <<<"$got")" = "$COURIER_IMAGE" ] || sec_die "$1: image mismatch"
  local a_want a_got
  a_want="$(jq -c '.extra_args' <<<"$2")"; a_got="$(jq -c '.config.extra_args' <<<"$got")"
  [ "$a_want" = "$a_got" ] || sec_die "$1: extra_args mismatch
    sent: $a_want
    got:  $a_got"
  sec_log "    echo-check ok (network=none, digest-pinned, args intact)"
}

existing="$(kapi read/ListDeployments | jq -r '.[].name' | sort)"
n=0
while IFS=$'\t' read -r sid sname; do
  [ -n "$sname" ] || continue
  for role in collect trigger; do
    dname="secaudit-${role}-${sname}"
    cfg="$(courier_config "$sid" "$role")"
    if [ "$DRY" = 1 ]; then
      echo "would ensure $dname on $sname:"
      jq -S '{network, volumes, command, extra_args, restart, send_alerts}' <<<"$cfg" | sed 's/^/    /'
      continue
    fi
    assert_no_collision "$sname" "$dname"
    if grep -qx "$dname" <<<"$existing"; then
      sec_log "  updating $dname"
      kapi write/UpdateDeployment "$(jq -nc --arg i "$dname" --argjson c "$cfg" '{id:$i, config:$c}')" >/dev/null
    else
      sec_log "  creating $dname"
      kapi write/CreateDeployment "$(jq -nc --arg n "$dname" --argjson c "$cfg" '{name:$n, config:$c}')" >/dev/null
    fi
    echo_check "$dname" "$cfg"
    if [ "$role" = trigger ]; then describe "$dname" "$DESC_TRIGGER"; else describe "$dname" "$DESC_COLLECT"; fi
    tag_it "$dname"
    n=$((n + 1))
  done
done < <(jq -r '.[] | [(.id // ._id["$oid"] // ""), .name] | @tsv' <<<"$servers")

[ "$DRY" = 1 ] && exit 0
sec_log "$n courier deployments in place"
sec_log "Next: install the bundle on each host (scripts/secaudit.sh bundle), then: scripts/secaudit.sh run collect"
