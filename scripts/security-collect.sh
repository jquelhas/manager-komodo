#!/usr/bin/env bash
# Harvest each host's audit report through its zero-privilege courier Deployment.
#
# The manager has no SSH to the app hosts and nothing on them listens for it. The only channel is
# Komodo: deploy a container whose entire job is `cat /r/report.ndjson`, then read its log back
# over the Core -> periphery link that already exists. No new port, no ACL change, no credential.
#
# Three outcomes per host, and keeping them DISTINCT is the point:
#   ok            exit 0 and a parseable report -> stored, and the findings become metrics
#   not_enrolled  exit != 0 and "No such file" -> the bundle was never installed there. This is a
#                 DELIBERATE state (the fleet is enrolled one machine at a time) and must never
#                 alert. Treating it as staleness would page about a decision someone made on
#                 purpose, which is how an alert stream gets ignored.
#   error         anything else -> alerting, because we genuinely do not know what is wrong.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/security-lib.sh"
cd "$SEC_REPO_DIR"
sec_load_env

POLL_TIMEOUT="${SECAUDIT_COLLECT_TIMEOUT:-120}"
ARCHIVE="$SEC_REPO_DIR/var/secaudit"
ONLY="${1:-}"          # optional: collect a single host

case "${SECAUDIT_ENABLED,,}" in
  1|true|yes) ;;
  *) sec_scan_skip collect disabled; exit 0 ;;
esac
sec_require_no_backup collect || exit 0

targets="$(sec_state_path targets.json)"
[ -s "$targets" ] || sec_die "no targets.json — run scripts/security-discover.sh first"

sec_scan_begin collect manager
# Seed from the existing file rather than starting empty. Collecting ONE host used to rewrite
# collect.json from scratch and erase every other host's status — including the not_enrolled flag
# that tells the exporter a machine is deliberately out of scope. The metrics for those hosts then
# simply vanished, which reads as "no data" rather than "not collected this time". Merge, never
# replace.
hosts_json='{}'
if [ -n "$ONLY" ] && [ -s "$(sec_state_path collect.json)" ]; then
  hosts_json="$(jq -c '.hosts // {}' "$(sec_state_path collect.json)" 2>/dev/null || echo '{}')"
fi
n_ok=0; n_err=0

while IFS=$'\t' read -r host scannable; do
  [ -n "$host" ] || continue
  [ -z "$ONLY" ] || [ "$ONLY" = "$host" ] || continue

  if [ "$scannable" != "1" ]; then
    # The host is not reachable for Komodo at all. Not an audit failure: leave the previous report
    # in place and say so. Zeroing findings because a host blipped would read as "all fixed".
    hosts_json="$(jq -c --arg h "$host" --argjson ts "$(date +%s)" \
      '. + {($h): {status:"unreachable", ts:$ts, detail:"Komodo reports the server is not Ok"}}' <<<"$hosts_json")"
    sec_warn "$host: unreachable, keeping any previous report"
    continue
  fi

  dep="secaudit-collect-${host}"
  sec_log "collecting from $host"
  if ! kapi execute/Deploy "$(jq -nc --arg d "$dep" '{deployment:$d}')" >/dev/null 2>&1; then
    hosts_json="$(jq -c --arg h "$host" --argjson ts "$(date +%s)" \
      '. + {($h): {status:"error", ts:$ts, detail:"Deploy failed (is the courier installed? scripts/setup-secaudit.sh)"}}' <<<"$hosts_json")"
    n_err=$((n_err + 1)); continue
  fi

  # Deploy returns as soon as the container starts, not when it finishes.
  deadline=$(( $(date +%s) + POLL_TIMEOUT )); state=""; code=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    insp="$(kapi read/InspectDeploymentContainer "$(jq -nc --arg d "$dep" '{deployment:$d}')" 2>/dev/null || true)"
    state="$(jq -r '.State.Status // ""' <<<"${insp:-{\}}" 2>/dev/null || echo "")"
    code="$(jq -r '.State.ExitCode // ""' <<<"${insp:-{\}}" 2>/dev/null || echo "")"
    [ "$state" = "running" ] || [ -z "$state" ] || break
    sleep 2
  done

  log="$(kapi read/GetDeploymentLog "$(jq -nc --arg d "$dep" '{deployment:$d, tail:5000}')" 2>/dev/null || true)"
  out="$(jq -r '.stdout // ""' <<<"${log:-{\}}" 2>/dev/null || echo "")"
  err="$(jq -r '.stderr // ""' <<<"${log:-{\}}" 2>/dev/null || echo "")"

  # Keep only the LAST complete report in the log, and never assume the log holds exactly one.
  # `execute/Deploy` recreates the container and so starts a fresh log, but StartDeployment — the
  # "Start" button in the Komodo UI, which is the one an operator actually sees on an exited
  # one-shot — reuses the container and APPENDS. Two clicks put two concatenated reports in the
  # log; storing both would double every finding count and pair the oldest `meta` with the newest
  # `end`. Slice from the last meta line instead.
  out="$(printf '%s' "$out" | python3 -c '
import sys
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
start = 0
for i, l in enumerate(lines):
    if l.lstrip().startswith("{\"k\":\"meta\""):
        start = i
print("\n".join(lines[start:]))
' 2>/dev/null || printf '%s' "$out")"
  if [ "$code" = "0" ] && [ -n "$out" ] && jq -e . >/dev/null 2>&1 <<<"$(head -n1 <<<"$out")"; then
    lines="$(grep -c . <<<"$out" || echo 0)"
    printf '%s\n' "$out" | grep . | sec_state_write "hosts/${host}.ndjson"
    # Archive a compressed copy so the per-CVE detail survives even though it never enters the
    # TSDB; pruned by SECAUDIT_RETENTION_DAYS below.
    mkdir -p "$ARCHIVE/$host"
    printf '%s\n' "$out" | grep . | gzip -9 > "$ARCHIVE/$host/$(date -u +%Y%m%dT%H%M%SZ).ndjson.gz"
    hosts_json="$(jq -c --arg h "$host" --argjson ts "$(date +%s)" --argjson l "$lines" \
      '. + {($h): {status:"ok", ts:$ts, lines:$l}}' <<<"$hosts_json")"
    n_ok=$((n_ok + 1))
  elif grep -qiE "no such file|can't open" <<<"$err"; then
    hosts_json="$(jq -c --arg h "$host" --argjson ts "$(date +%s)" \
      '. + {($h): {status:"not_enrolled", ts:$ts, detail:"no report on the host — the bundle is not installed"}}' <<<"$hosts_json")"
    sec_log "  $host: not enrolled (deliberate — install with scripts/secaudit.sh bundle)"
  else
    hosts_json="$(jq -c --arg h "$host" --arg d "${err:0:200}" --argjson ts "$(date +%s)" --arg c "$code" \
      '. + {($h): {status:"error", ts:$ts, exit_code:$c, detail:$d}}' <<<"$hosts_json")"
    sec_warn "  $host: collect failed (exit ${code:-?}): ${err:0:120}"
    n_err=$((n_err + 1))
  fi
done < <(jq -r '.targets[] | select(.host != "manager") | [.host, (.scannable|tostring)] | @tsv' "$targets")

# The manager audits itself locally — no courier, no Komodo round trip.
if [ -z "$ONLY" ] || [ "$ONLY" = "manager" ]; then
  local_report="/var/lib/secaudit/report.ndjson"
  if [ -r "$local_report" ]; then
    lines="$(grep -c . "$local_report" || echo 0)"
    sec_state_write "hosts/manager.ndjson" < "$local_report"
    hosts_json="$(jq -c --argjson ts "$(date +%s)" --argjson l "$lines" \
      '. + {manager: {status:"ok", ts:$ts, lines:$l}}' <<<"$hosts_json")"
    n_ok=$((n_ok + 1))
  else
    hosts_json="$(jq -c --argjson ts "$(date +%s)" \
      '. + {manager: {status:"not_enrolled", ts:$ts, detail:"no local report"}}' <<<"$hosts_json")"
  fi
fi

jq -n --argjson ts "$(date +%s)" --argjson h "$hosts_json" '{schema:1, ts:$ts, hosts:$h}' \
  | sec_state_write collect.json

# Prune the archive. Current state is fixed-size; only this grows.
find "$ARCHIVE" -type f -name '*.ndjson.gz' -mtime "+${SECAUDIT_RETENTION_DAYS}" -delete 2>/dev/null || true

sec_log "collected $n_ok host(s), $n_err error(s)"
sec_scan_end "$([ "$n_err" -eq 0 ] && echo 1 || echo 0)" "$n_ok"
