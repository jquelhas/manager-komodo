#!/usr/bin/env bash
# Operator CLI for the security auditor. This is the interface for everything done on demand;
# the systemd timers only invoke the same scripts. See docs/plan/secaudit.md.
#
#   secaudit.sh run [all|discovery|fast|collect] [--dry-run]
#   secaudit.sh status                      what ran, when, and whether it is stale
#   secaudit.sh show ports|listeners|drift|suppressions
#   secaudit.sh show lynis|bench <host>    per-finding detail, read back from the collected report
#   secaudit.sh metrics                     the exact exposition VictoriaMetrics scrapes
#   secaudit.sh audit <host>                ask a host to audit itself NOW, from here
#   secaudit.sh bundle [--serve]            package the host bundle; --serve publishes it as a
#                                           one-time link so hosts install with a single curl
#
# Scans from later phases (collect/ports/tls/web) are rejected with a clear message rather than
# silently doing nothing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/security-lib.sh"
cd "$SEC_REPO_DIR"

DRY=0
SERVE=0
failed=""
args=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --serve)   SERVE=1 ;;
    *) args+=("$a") ;;
  esac
done
set -- ${args[@]+"${args[@]}"}
cmd="${1:-status}"; sub="${2:-}"

IMPLEMENTED="discovery fast collect"
PLANNED="ports tls web"

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
      collect)   to_run="collect" ;;
      ports|tls|web)
        sec_die "scan '$scan' is not implemented yet (phase $( [ "$scan" = collect ] && echo 2 || echo 3+ ) in docs/plan/secaudit.md)" ;;
      *) sec_die "unknown scan '$scan' (implemented: $IMPLEMENTED; planned: $PLANNED)" ;;
    esac
    for s in $to_run; do
      # Scan names appear in metrics and alerts; script names follow the file layout. They are not
      # always the same word, so map explicitly rather than interpolating the scan name.
      case "$s" in
        discovery) script="$SEC_REPO_DIR/scripts/security-discover.sh" ;;
        fast)      script="$SEC_REPO_DIR/scripts/security-fast.sh" ;;
        collect)   script="$SEC_REPO_DIR/scripts/security-collect.sh" ;;
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
      # The per-finding detail deliberately lives in the collected NDJSON and never in the TSDB
      # (one series per lynis test per host would be cardinality for nothing). These two read it
      # back, so answering "what did it actually find" does not need a hand-written jq.
      lynis|bench)
        host="${3:-}"
        [ -n "$host" ] || sec_die "usage: secaudit.sh show $sub <host>   (hosts: $(ls "$(sec_state_path hosts)" 2>/dev/null | sed 's/\.ndjson$//' | tr '\n' ' '))"
        f="$(sec_state_path "hosts/$host.ndjson")"
        [ -f "$f" ] || sec_die "no collected report for '$host' — run: secaudit.sh run collect"
        # `detail` is an empty STRING (not null) on most lynis suggestions, so `//` does not fall
        # through to `desc`. Getting this wrong prints a page of blank descriptions.
        jq -r --arg k "$sub" 'select(.k==$k)
              | .t = (if (.detail // "") == "" then (.desc // "") else .detail end)
              | "\(.severity // "-")\t\(.section // "-")\t\(.test_id // .id // "-")\t\(.t)"' "$f" \
          | sort -u | column -t -s$'\t' ;;
      *) sec_die "show what? ports|listeners|drift|suppressions|lynis <host>|bench <host>" ;;
    esac
    ;;

  bundle)
    # Package the host bundle so an operator can carry it to a machine the manager cannot reach.
    # The manager deliberately has no SSH access to the app hosts (root SSH from here to the whole
    # fleet would be a wider privilege path than anything this auditor protects), so installation
    # is a carry, not a push.
    out="${SECAUDIT_BUNDLE_OUT:-/tmp}/secaudit-bundle.tgz"
    tar czf "$out" -C "$SEC_REPO_DIR/bootstrap" install-secaudit.sh secaudit
    chmod 0644 "$out"
    sum="$(sha256sum "$out" | cut -d' ' -f1)"
    ver="$(sed -n 's/^SECAUDIT_\([A-Z]*\)_VERSION=\(.*\)$/\1 \2/p' "$SEC_REPO_DIR/bootstrap/secaudit/versions.env" | tr '\n' ' ')"
    echo "bundle:  $out  ($(du -h "$out" | cut -f1))"
    echo "sha256:  $sum"
    echo "pinned:  $ver"
    echo
    # --serve: publish the bundle as a one-time link on the PUBLIC provisioning endpoint, so each
    # host installs with a single curl instead of an scp. This deliberately does NOT use the mesh.
    #
    # The obvious idea is to serve it from 100.64.0.1 over the tailnet, but docker/headscale/
    # acl.hujson opens exactly ONE port from `tag:segcore` to the manager -- 443, for the
    # maintenance-silence endpoint (added 2026-09-08) -- and nothing else. App hosts cannot reach
    # a bundle server on any other port, by design. That deny is the control stopping a compromised
    # app host — the public-facing, highest-risk machines in the fleet — from pivoting into the
    # control plane,
    # which holds the Komodo API (deploy on every host), the step-ca root and every secret. This
    # auditor's own UnexpectedOpenPortMesh alert exists to detect exactly that rule appearing.
    # Opening it to deliver the auditor would be using the tool to undo what it measures.
    #
    # The public endpoint has none of that cost and is already proven by add-host.sh: a real
    # Let's Encrypt certificate (so no --cacert dance, unlike anything on *.apps.internal), the
    # uuid IS the capability, a TTL, rate limiting, and Traefik path-scoping. The bundle carries no
    # secrets, so it is strictly less sensitive than the onboarding script this endpoint already
    # serves — that one embeds a live auth key.
    if [ "${SERVE:-0}" = "1" ]; then
      store="$SEC_REPO_DIR/provisioning/store"
      [ -d "$store" ] || sec_die "store dir $store missing (bring the provisioning service up first)"
      [ -w "$store" ] || sec_die "store dir $store not writable by $(id -un)"
      domain="$(env_get PUBLIC_DOMAIN)"; : "${domain:?PUBLIC_DOMAIN not set in .env}"
      uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
      ttl="${SECAUDIT_LINK_TTL:-3600}"
      now="$(date +%s)"
      tmp="$(mktemp -d "$store/.tmp.XXXXXX")"
      {
        echo '#!/usr/bin/env bash'
        echo '# secaudit host bundle, self-extracting. Generated by scripts/secaudit.sh bundle --serve.'
        echo '# Unpacks into a temp dir and runs install-secaudit.sh with whatever arguments follow.'
        echo 'set -euo pipefail'
        echo '[ "$(id -u)" = 0 ] || { echo "run me as root (sudo)" >&2; exit 1; }'
        echo 'd="$(mktemp -d)"; trap '"'"'rm -rf "$d"'"'"' EXIT'
        echo 'base64 -d <<'"'"'B64EOF'"'"' | tar xz -C "$d"'
        base64 -w100 "$out"
        echo 'B64EOF'
        echo 'exec "$d/install-secaudit.sh" "$@"'
      } > "$tmp/install.sh"
      chmod 600 "$tmp/install.sh"
      printf '{"created_at": %s, "expires_at": %s, "role": "secaudit", "status": "active"}\n' \
        "$now" "$((now + ttl))" > "$tmp/meta.json"
      chmod 700 "$tmp"
      mv "$tmp" "$store/$uuid"
      url="https://${domain}/provisioning/${uuid}/install.sh"
      echo "served:  $url"
      echo "expires: in $((ttl / 60)) min   (the uuid IS the secret; a GET does not burn it, so the"
      echo "         same link serves the dry run and the real install)"
      echo
      echo "On each host, as an operator with sudo:"
      echo
      echo "  sudo bash -c \"\$(curl -fsSL $url)\" -- --dry-run"
      echo "  sudo bash -c \"\$(curl -fsSL $url)\" -- --no-enable"
      echo "  sudo systemctl start secaudit-host.service && journalctl -u secaudit-host.service -f"
      echo
      echo "To revoke early:  rm -rf $store/$uuid"
      echo
    fi
    if [ "${SERVE:-0}" = "0" ]; then
    echo "Copy it to the host, then install there as root. The bundle carries only the installer"
    echo "and run.py; the scanners themselves are fetched on the host and SHA-256 verified."
    echo "(Or publish it as a one-time link instead: scripts/secaudit.sh bundle --serve)"
    echo
    # Print a real command per known target rather than a template to adapt by hand. The SSH port
    # is NOT uniform across this fleet, so it is left as <port> deliberately: filling in a wrong
    # one silently connects nowhere.
    if [ -s "$(sec_state_path targets.json)" ]; then
      while IFS=$'\t' read -r host ip; do
        [ -n "$ip" ] || continue
        echo "  # $host"
        echo "  scp -P <port> $out <user>@$ip:/tmp/"
        echo "  ssh -p <port> <user>@$ip 'cd /tmp && tar xzf secaudit-bundle.tgz && sudo ./install-secaudit.sh --dry-run'"
        echo
      done < <(jq -r '.targets[] | select(.host != "manager" and .public_ip != "") | [.host, .public_ip] | @tsv' "$(sec_state_path targets.json)")
    fi
    fi
    cat <<'EOM'
Order of operations on each host:
  1. --dry-run first, and read it.
  2. sudo ./install-secaudit.sh --no-enable        (installs, starts nothing)
  3. sudo systemctl start secaudit-host.service    (ONE run, watched; 5-10 min)
     journalctl -u secaudit-host.service -f
  4. Check it: sudo grep -c . /var/lib/secaudit/report.ndjson
               sudo grep '"k":"tool_error"' /var/lib/secaudit/report.ndjson || echo "clean"
  5. Only then: sudo systemctl enable --now secaudit-host.timer secaudit-host.path

On the ONE host chosen as the external vantage point on the manager, add nmap and re-run the
installer with the targets. Re-running is cheap and idempotent: the scanners are already at the
pinned versions, so it only rewrites the unit. Add --no-enable if you are not ready for the timer.
  sudo apt-get install -y nmap
  # if you installed from the scp'd tarball:
  sudo ./install-secaudit.sh --perimeter-targets "manager_public=<PUBLIC_IP> manager_mesh=100.64.0.1"
  # if you installed from the served link (there is no install-secaudit.sh on disk — the bundle
  # self-extracts into a temp dir and is removed; pass the arguments through the same one-liner):
  sudo bash -c "$(curl -fsSL <the served URL>)" -- --perimeter-targets "manager_public=<PUBLIC_IP> manager_mesh=100.64.0.1"
The mesh target is expected to find NOTHING: the Headscale ACL has no app-host -> manager rule, so
an open port there is an ACL regression to fix in acl.hujson, never a baseline entry.

To remove everything later:  sudo ./install-secaudit.sh --uninstall
EOM
    ;;

  audit)
    # Ask a host to audit itself, now, from here — no SSH and no root exec anywhere.
    #
    # The manager deploys a courier whose only capability is `touch` on one sentinel file inside a
    # write-only subdirectory; a systemd .path unit on the host watches that file and starts the
    # audit. The container has no network, no capabilities, no docker.sock, and cannot read or
    # replace the report it is asking to be regenerated. The worst an abuse of this path achieves
    # is requesting an audit.
    # This is the only command here that talks to Komodo directly; every other path delegates to a
    # security-*.sh, each of which loads the credentials itself. Without this the API call goes out
    # unauthenticated and returns 401 — which never showed in testing, because an interactive shell
    # that had already sourced the lib exported the keys to every child process.
    sec_load_env
    host="${sub:-}"
    [ -n "$host" ] || sec_die "which host? scripts/secaudit.sh audit <host>   (see: secaudit.sh status)"
    [ "$host" != "manager" ] || sec_die "the manager audits itself locally: sudo systemctl start secaudit-host.service"
    dep="secaudit-trigger-${host}"
    before="$(head -1 "$(sec_state_path "hosts/${host}.ndjson")" 2>/dev/null | jq -r '.runid // ""' || true)"
    if [ "$DRY" = "1" ]; then
      echo "would deploy $dep, then poll for a new runid (current: ${before:-none})"
      exit 0
    fi
    sec_log "asking $host to audit itself"
    kapi execute/Deploy "$(jq -nc --arg d "$dep" '{deployment:$d}')" >/dev/null \
      || sec_die "could not deploy $dep (is the courier installed? scripts/setup-secaudit.sh)"
    # The trigger is fire-and-forget: the host's .path unit starts the audit, which takes minutes.
    # Poll by collecting until the run id changes; that is the only signal the manager can see,
    # since it has no view of the host's systemd.
    deadline=$(( $(date +%s) + ${SECAUDIT_AUDIT_WAIT:-1200} ))
    sec_log "waiting for a new report (the run takes 5-10 min; Ctrl-C is safe, it keeps going)"
    while [ "$(date +%s)" -lt "$deadline" ]; do
      sleep 45
      "$SEC_REPO_DIR/scripts/security-collect.sh" "$host" >/dev/null 2>&1 || true
      after="$(head -1 "$(sec_state_path "hosts/${host}.ndjson")" 2>/dev/null | jq -r '.runid // ""' || true)"
      # A new run id alone is NOT enough. run.py checkpoints the report after every step, so the id
      # changes about a second into a run that still has minutes to go — polling on the id alone
      # reported success over a report with two of four steps done. Wait for the run to declare
      # itself complete.
      done_ok="$(grep '"k":"end"' "$(sec_state_path "hosts/${host}.ndjson")" 2>/dev/null | tail -1 | jq -r '.ok // false' || echo false)"
      if [ -n "$after" ] && [ "$after" != "$before" ] && [ "$done_ok" = "true" ]; then
        sec_log "new report: $after (complete)"
        jq -r 'select(.k=="end") | "  complete=\(.ok) duration=\(.duration)s"' \
          "$(sec_state_path "hosts/${host}.ndjson")" | tail -1
        jq -r 'select(.k=="tool_error") | "  error: \(.tool): \(.msg[0:100])"' \
          "$(sec_state_path "hosts/${host}.ndjson")" || true
        echo
        echo "$(run_exporter | grep -E "^secaudit_(port_unexpected|unexpected_ports|lynis_hardening_index|bench_score|packages_vulnerable).*$host" || true)"
        exit 0
      fi
    done
    sec_warn "no new report within the wait window. The trigger was delivered; check on the host:"
    sec_warn "  systemctl status secaudit-host.path secaudit-host.service"
    exit 1
    ;;

  metrics) run_exporter ;;
  -h|--help|help) usage 0 ;;
  *) sec_die "unknown command '$cmd' (run|audit|status|show|metrics|bundle)" ;;
esac
