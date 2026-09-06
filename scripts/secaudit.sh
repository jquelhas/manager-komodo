#!/usr/bin/env bash
# Operator CLI for the security auditor. This is the interface for everything done on demand;
# the systemd timers only invoke the same scripts. See docs/plan/secaudit.md.
#
#   secaudit.sh run [all|discovery|fast] [--dry-run]
#   secaudit.sh status                      what ran, when, and whether it is stale
#   secaudit.sh show ports|listeners|drift|suppressions
#   secaudit.sh metrics                     the exact exposition VictoriaMetrics scrapes
#
# Scans from later phases (collect/ports/tls/web) are rejected with a clear message rather than
# silently doing nothing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/security-lib.sh"
cd "$SEC_REPO_DIR"

DRY=0
failed=""
args=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    *) args+=("$a") ;;
  esac
done
set -- ${args[@]+"${args[@]}"}
cmd="${1:-status}"; sub="${2:-}"

IMPLEMENTED="discovery fast"
PLANNED="collect ports tls web"

usage() {
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# The exporter is the single source of truth for verdicts (it applies baseline + suppressions), so
# the CLI asks it rather than re-implementing the policy. Run it against the repo's own directory.
run_exporter() {
  SECURITY_DIR="$SEC_REPO_DIR/security" python3 - <<'PY'
import os, sys, types
src = open("provisioning/server.py").read()
m = types.ModuleType("srv"); m.__dict__["__name__"] = "srv"
exec(compile(src, "provisioning/server.py", "exec"), m.__dict__)
sys.stdout.write(m.security_metrics_text())
PY
}

case "$cmd" in
  run)
    scan="${sub:-all}"
    case "$scan" in
      all)       to_run="$IMPLEMENTED" ;;
      discovery) to_run="discovery" ;;
      fast)      to_run="fast" ;;
      collect|ports|tls|web)
        sec_die "scan '$scan' is not implemented yet (phase $( [ "$scan" = collect ] && echo 2 || echo 3+ ) in docs/plan/secaudit.md)" ;;
      *) sec_die "unknown scan '$scan' (implemented: $IMPLEMENTED; planned: $PLANNED)" ;;
    esac
    for s in $to_run; do
      # Scan names appear in metrics and alerts; script names follow the file layout. They are not
      # always the same word, so map explicitly rather than interpolating the scan name.
      case "$s" in
        discovery) script="$SEC_REPO_DIR/scripts/security-discover.sh" ;;
        fast)      script="$SEC_REPO_DIR/scripts/security-fast.sh" ;;
        *)         sec_die "no script mapped for scan '$s'" ;;
      esac
      if [ "$DRY" = "1" ]; then
        echo "would run: $script"
        continue
      fi
      sec_log "running $s"
      # Deliberately NOT fail-fast: one broken scan must not hide whether the others still work,
      # which is exactly what an operator needs to know. Failures are reported and re-raised at
      # the end.
      if ! "$script"; then
        sec_warn "scan '$s' failed (exit $?)"
        failed="$failed $s"
      fi
    done
    if [ -n "${failed# }" ]; then
      sec_die "failed:${failed}"
    fi
    ;;

  status)
    f="$(sec_state_path scan-status.json)"
    [ -s "$f" ] || sec_die "no state yet — run: scripts/secaudit.sh run all"
    # Budgets live in the exporter, so staleness is read back from the metrics rather than
    # duplicated here.
    metrics="$(run_exporter)"
    printf '%-14s %-9s %-8s %-7s %-9s %s\n' SCAN HOST STATUS AGE BUDGET TARGETS
    # Budgets are NOT restated here: they are read back from secaudit_scan_max_age_seconds in the
    # metrics, so this table and the alert rules can never disagree on what "stale" means.
    budgets="$(echo "$metrics" | sed -nE 's/^secaudit_scan_max_age_seconds\{scan="([^"]+)"\} ([0-9]+)$/\1=\2/p' | paste -sd, -)"
    SECAUDIT_BUDGETS="$budgets" python3 - "$f" <<'PYSTATUS'
import json, os, sys, time
d = json.load(open(sys.argv[1]))
budgets = {}
for pair in (os.environ.get("SECAUDIT_BUDGETS") or "").split(","):
    k, _, v = pair.partition("=")
    if k and v.isdigit():
        budgets[k] = int(v)
now = time.time()
for e in sorted(d.get("scans", {}).values(), key=lambda x: (x.get("scan", ""), x.get("host", ""))):
    ls = e.get("last_success")
    age = int(now - ls) if ls else None
    b = budgets.get(e.get("scan", ""), 0)
    stale = "STALE" if (age is None or (b and age > b)) else "ok"
    print("%-14s %-9s %-8s %-7s %-9s %s" % (
        e.get("scan", ""), e.get("host", ""),
        ("ok" if e.get("status") == 1 else "FAIL"),
        (f"{age}s" if age is not None else "never"), (f"{b}s" if b else "-"),
        f"{e.get('targets', 0)} [{stale}]"))
for k, v in sorted(d.get("skips", {}).items()):
    print("skipped: %s x%s" % (k.replace("|", " / "), v))
PYSTATUS
    # A scan can be stale for two very different reasons: it is broken, or it was never scheduled.
    # The second is invisible from the metrics alone and cost us 42h and an alert e-mail once, so
    # say it here rather than making somebody deduce it.
    if ! systemctl is-enabled --quiet manager-security-fast.timer 2>/dev/null; then
      sec_warn "manager-security-fast.timer is NOT enabled — nothing runs on its own."
      sec_warn "  sudo cp scripts/systemd/manager-security-fast.{service,timer} /etc/systemd/system/"
      sec_warn "  sudo systemctl daemon-reload && sudo systemctl enable --now manager-security-fast.timer"
    elif ! systemctl is-active --quiet manager-security-fast.timer 2>/dev/null; then
      sec_warn "manager-security-fast.timer is enabled but not active — start it:"
      sec_warn "  sudo systemctl start manager-security-fast.timer"
    fi
    echo
    echo "$metrics" | grep -E '^secaudit_(unexpected_ports|discovery_ok|discovery_shrunk|exporter_state_error|suppression_invalid|internal_name_misconfigured)' || true
    ;;

  show)
    case "$sub" in
      listeners) jq -r '.listeners[] | "\(.proto)/\(.port)\t\(.addr)\t\(.process)"' "$(sec_state_path listeners.json)" | column -t ;;
      ports)     run_exporter | grep -E '^secaudit_port_(open|unexpected|missing)' || echo "no exposed ports recorded" ;;
      drift)     jq -r '"routers: \(.routers|length)", (.findings[]? | "MISSING \(.missing)\t\(.name)")' "$(sec_state_path drift.json)" ;;
      suppressions) run_exporter | grep -E '^secaudit_suppression' || echo "none" ;;
      *) sec_die "show what? ports|listeners|drift|suppressions" ;;
    esac
    ;;

  metrics) run_exporter ;;
  -h|--help|help) usage 0 ;;
  *) sec_die "unknown command '$cmd' (run|status|show|metrics)" ;;
esac
