#!/usr/bin/env python3
"""secaudit host bundle — the audit that has to run ON the machine.

Runs as root from secaudit-host.service and writes ONE NDJSON file to
$SECAUDIT_STATE/report.ndjson. Everything here is read-only auditing: it inspects, it never
installs, reconfigures, restarts or removes anything. The only paths it writes are
$SECAUDIT_STATE and $SECAUDIT_LOG, and the systemd unit enforces that with
ProtectSystem=strict + ReadWritePaths — so this is a kernel guarantee, not a promise from a script.

THIS FILE RUNS AS ROOT. It is the most review-sensitive file in the repo. It therefore:
  - reads nothing from outside $SECAUDIT_ROOT,
  - takes no network parameters (the only outbound traffic is, on the designated host, an nmap of
    addresses fixed in the unit's environment),
  - never runs `apt-get update`/`upgrade` — refreshing the package index is a state change and an
    operator's decision, never a side effect of an audit. The pending-vulnerable-package count
    comes from the apt metadata already on disk.

It emits raw facts. Classifying a bind address, comparing against a baseline and applying
suppressions all happen on the manager at scrape time, so policy changes never touch a host.

Each step is isolated: a tool that fails or times out emits {"k":"tool_error"} and the others
still run. A partial report is far more useful than none, and the manager can see exactly which
part is missing.

RUN IT THROUGH SYSTEMD, NOT DIRECTLY:  systemctl start secaudit-host.service
The unit carries the cgroup caps (MemoryMax=1G) and the filesystem containment. Running
`./run.py` by hand bypasses both. That is not hypothetical: on 2026-09-06 a manual run on the
3.8 GB manager OOM-killed VictoriaMetrics and took the host down. The step that made that possible
(image CVE scanning) has since moved to the application's CI, but the unit is still the way in.
"""
import collections
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = os.environ.get("SECAUDIT_ROOT", "/opt/secaudit")
STATE = os.environ.get("SECAUDIT_STATE", "/var/lib/secaudit")
LOGDIR = os.environ.get("SECAUDIT_LOG", "/var/log/secaudit")
TRIGGER = os.path.join(STATE, "trigger.d", "run")

# Caps. Detail lines are for the archive on the manager; the metrics only ever use the summaries,
# so truncating detail costs nothing that alerts depend on — and it is reported when it happens.
# Addresses to scan from here, "name=ip" separated by spaces. Set only on the designated
# cross-scan host; empty everywhere else.
PERIMETER_TARGETS = os.environ.get("SECAUDIT_PERIMETER_TARGETS", "").strip()
PERIMETER_PORTS = os.environ.get(
    "SECAUDIT_PERIMETER_PORTS", "1-1024,3000,5432,8120,8428,8880,9093,9120,9187,60022")
PERIMETER_MAX_RATE = os.environ.get("SECAUDIT_PERIMETER_MAX_RATE", "100")

TIMEOUTS = {"listeners": 60, "lynis": 900, "bench": 600, "perimeter": 900}
# Comma-separated subset of steps to run; empty means all. Exists for staged rollout: the first
# run on a new machine should prove the cheap steps before the expensive one is let loose on it.
STEPS = [x.strip() for x in os.environ.get("SECAUDIT_STEPS", "").split(",") if x.strip()]

_records = []
_truncated = []
_runid = ""
_t0 = time.time()


def emit(**rec):
    _records.append(rec)


def write_report(complete):
    """Write the NDJSON atomically. Called after EVERY step, not just at the end.

    Learned the hard way on 2026-09-06: the first full run on the manager was killed by
    TimeoutStartSec after 28 minutes, and because the report was only written at the end, all of it
    was lost AND the manager kept serving the previous run's data with no indication that anything
    had gone wrong. A partial report that says it is partial is worth far more than a lost one, so
    the completeness flag travels IN the report and the manager turns it into a metric.
    """
    dst = os.path.join(STATE, "report.ndjson")
    tmp = dst + ".tmp"
    tail = dict(k="end", runid=_runid, n=len(_records) + 1, ok=bool(complete),
                partial=not complete, duration=round(time.time() - _t0, 1))
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            for rec in _records:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            fh.write(json.dumps(tail, separators=(",", ":")) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, dst)                       # atomic: the courier may be reading
    except OSError as e:
        print(f"secaudit: failed to write report: {e}", file=sys.stderr)


def _on_term(signum, _frame):
    """systemd sends SIGTERM on TimeoutStartSec. Flush what we have, marked partial, then go."""
    emit(k="tool_error", tool="run", msg=f"terminated by signal {signum} — report is partial")
    write_report(complete=False)
    os._exit(143)


def run(cmd, timeout, cwd=None, env=None):
    """Return (rc, stdout, stderr). rc is -1 on timeout, -2 if the binary is missing."""
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except (FileNotFoundError, PermissionError) as e:
        return -2, "", str(e)


def tool_error(tool, msg):
    emit(k="tool_error", tool=tool, msg=str(msg)[:400])


# --------------------------------------------------------------------------------------------
# 1. Listeners. The socket table, not nmap: traffic to your own addresses takes the loopback path
# and bypasses any filtering, and nmap reports reachability but never the BIND address — which is
# the entire question here. Running as root also fills in the process, which is what makes the
# resulting alert actionable.
# --------------------------------------------------------------------------------------------
def step_listeners():
    rc, out, err = run(["ss", "-lntupH"], TIMEOUTS["listeners"])
    if rc != 0:
        return tool_error("ss", err or f"rc={rc}")
    n = 0
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto, state, local = f[0], f[1], f[4]
        if proto not in ("tcp", "udp") or (proto == "tcp" and state != "LISTEN"):
            continue
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        addr = addr.split("%")[0]           # strip the interface scope: 127.0.0.53%lo
        family = 6 if addr.startswith("[") else 4
        m = re.search(r'users:\(\("([^"]+)"', line)
        emit(k="listen", proto=proto, family=family, addr=addr.strip("[]"),
             port=int(port), process=m.group(1) if m else "")
        n += 1
    rc, out, _ = run(["ip", "-o", "addr"], 30)
    if rc == 0:
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 4 and f[2] in ("inet", "inet6"):
                emit(k="addr", dev=f[1], cidr=f[3])
    emit(k="step_ok", step="listeners", n=n)


# --------------------------------------------------------------------------------------------
# 2. Lynis — OS hardening. Report format (verified against 3.1.7):
#   warning[]=TEST-ID|description|solution|url|
#   suggestion[]=TEST-ID|description|solution|url|
#   hardening_index=65 / vulnerable_packages_found=0 / lynis_version=3.1.7
# Both warnings AND suggestions are emitted as findings: Lynis puts almost everything in
# suggestions (41 vs 1 on the manager), so treating suggestions as decoration would throw away the
# substance. One test id can produce several distinct suggestions, so the solution field is
# carried as `detail` and is part of the finding's identity.
# --------------------------------------------------------------------------------------------
def step_lynis():
    lynis_dir = os.path.join(ROOT, "lynis")
    report = os.path.join(LOGDIR, "lynis-report.dat")
    logfile = os.path.join(LOGDIR, "lynis.log")
    for f in (report, logfile):
        try:
            os.path.exists(f) and os.remove(f)   # truncate per run: these must not accumulate
        except OSError:
            pass
    rc, _out, err = run([os.path.join(lynis_dir, "lynis"), "audit", "system",
                         "--cronjob", "--logfile", logfile, "--report-file", report],
                        TIMEOUTS["lynis"], cwd=lynis_dir)
    if not os.path.exists(report):
        return tool_error("lynis", err or f"no report produced (rc={rc})")
    n = 0
    try:
        with open(report, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                key, _, val = line.partition("=")
                if key in ("warning[]", "suggestion[]"):
                    parts = val.split("|")
                    test_id = parts[0].strip() if parts else ""
                    if not test_id:
                        continue
                    desc = parts[1].strip() if len(parts) > 1 else ""
                    detail = parts[2].strip() if len(parts) > 2 else ""
                    if detail == "-":
                        detail = ""
                    emit(k="lynis", severity="warning" if key.startswith("warning") else "suggestion",
                         test_id=test_id, section=test_id.split("-")[0],
                         detail=detail[:80], desc=desc[:160])
                    n += 1
                elif key == "hardening_index":
                    try:
                        emit(k="lynis_meta", hardening_index=int(val))
                    except ValueError:
                        pass
                elif key == "vulnerable_packages_found":
                    try:
                        emit(k="packages", vulnerable=int(val))
                    except ValueError:
                        pass
                elif key == "lynis_version":
                    emit(k="tool", name="lynis", version=val.strip())
    except OSError as e:
        return tool_error("lynis", e)
    emit(k="step_ok", step="lynis", n=n)


# --------------------------------------------------------------------------------------------
# 3. docker-bench-security — CIS Docker Benchmark.
# `-l /dev/stdout` does NOT work: the tool writes its JSON to "$logger.json", so that would land in
# /dev/stdout.json. Write to a real path and read the .json next to it. The JSON is assembled with
# printf upstream and is known to come out invalid on some paths, so the text log is parsed as a
# fallback — without it, one malformed check silently zeroes the whole benchmark and the dashboard
# goes green.
# --------------------------------------------------------------------------------------------
_BENCH_TEXT = re.compile(r"^\[(WARN|PASS|INFO|NOTE)\]\s+([0-9][0-9.]*)\s+-\s+(.*)$")


def step_bench():
    bench_dir = os.path.join(ROOT, "docker-bench")
    log = os.path.join(LOGDIR, "docker-bench.log")
    for f in (log, log + ".json"):
        try:
            os.path.exists(f) and os.remove(f)
        except OSError:
            pass
    script = os.path.join(bench_dir, "docker-bench-security.sh")
    if not os.path.exists(script):
        return tool_error("docker-bench", "not installed")
    rc, out, err = run(["bash", script, "-b", "-l", log], TIMEOUTS["bench"], cwd=bench_dir)
    n, degraded = 0, False
    parsed = False
    jpath = log + ".json"
    if os.path.exists(jpath):
        try:
            with open(jpath, "r", encoding="utf-8", errors="replace") as fh:
                doc = json.load(fh)
            for test in doc.get("tests") or []:
                section = str(test.get("id", ""))
                for res in test.get("results") or []:
                    level = str(res.get("result", "")).upper()
                    if level != "WARN":
                        continue        # only failures are findings; PASS/INFO/NOTE are noise
                    emit(k="bench", id=str(res.get("id", "")), section=section,
                         desc=str(res.get("desc", ""))[:160])
                    n += 1
            if doc.get("checks") is not None:
                emit(k="bench_meta", score=doc.get("score", 0), checks=doc.get("checks", 0))
            parsed = True
        except (OSError, ValueError):
            parsed = False
    if not parsed:
        # Fallback: the stable text form. Less structure, but a real benchmark beats a green zero.
        degraded = True
        try:
            text = open(log, "r", encoding="utf-8", errors="replace").read() if os.path.exists(log) else out
        except OSError:
            text = out
        for line in text.splitlines():
            m = _BENCH_TEXT.match(line.strip())
            if m and m.group(1) == "WARN":
                emit(k="bench", id=m.group(2), section=m.group(2).split(".")[0],
                     desc=m.group(3)[:160])
                n += 1
        if n == 0 and rc != 0:
            return tool_error("docker-bench", err or f"rc={rc}, no parseable output")
    emit(k="step_ok", step="bench", n=n, degraded=degraded)


# --------------------------------------------------------------------------------------------
# 5. Perimeter cross-scan. Only on the designated host, and only against addresses fixed in the
# unit's environment. -sT (connect) needs no raw-socket capability and is the more faithful answer
# to "is this reachable from outside" anyway. The mesh target is expected to find NOTHING: the
# Headscale ACL has no app-host -> manager rule, so an open port there is an ACL regression and
# must be fixed in acl.hujson, never accepted into the baseline.
# --------------------------------------------------------------------------------------------
def step_perimeter():
    if not PERIMETER_TARGETS:
        return
    if not shutil.which("nmap"):
        return tool_error("nmap", "not installed (apt-get install nmap on the cross-scan host)")
    for item in PERIMETER_TARGETS.split():
        name, _, ip = item.partition("=")
        if not ip:
            continue
        # Assert the route: if a future routing change sent this through tailscale0, a "public"
        # scan would silently become a mesh scan and report a falsely clean perimeter.
        rc, rout, _e = run(["ip", "route", "get", ip], 15)
        emit(k="route", target=name, ip=ip, via=rout.strip().split("\n")[0][:200] if rc == 0 else "")
        rc, out, err = run(["nmap", "-Pn", "-sT", "-n", "--open",
                            "--max-rate", PERIMETER_MAX_RATE, "--max-retries", "2",
                            "--host-timeout", "300s", "-p", PERIMETER_PORTS, "-oG", "-", ip],
                           TIMEOUTS["perimeter"])
        if rc != 0:
            tool_error("nmap", f"{name}: {(err or '')[:200]}")
            continue
        n = 0
        for line in out.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            for spec in line.split("Ports:", 1)[1].split(","):
                f = spec.strip().split("/")
                if len(f) >= 3 and f[1] == "open":
                    emit(k="port", target=name, ip=ip, port=int(f[0]),
                         proto=f[2] or "tcp", service=(f[4] if len(f) > 4 else ""))
                    n += 1
        emit(k="scan_ok", target=name, ip=ip, n=n)


def summarise():
    """Human-readable digest of the last report. Read-only, needs no privileges.

    Exists because the manager cannot reach these hosts, so whoever is standing on one needs a way
    to see whether the run was any good without pasting a wall of jq into a root shell.
    """
    path = os.path.join(STATE, "report.ndjson")
    try:
        recs = [json.loads(l) for l in open(path, "r", encoding="utf-8") if l.strip()]
    except OSError as e:
        print(f"no report at {path}: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"report at {path} is not valid NDJSON: {e}", file=sys.stderr)
        return 1

    def of(k):
        return [r for r in recs if r.get("k") == k]

    meta = (of("meta") or [{}])[0]
    end = (of("end") or [{}])[-1]
    state = "COMPLETE" if end.get("ok") else "PARTIAL"
    print(f"run {meta.get('runid', '?')} on {meta.get('host', '?')}: {state} "
          f"in {end.get('duration', '?')}s, {len(recs)} records")

    for r in of("step_ok"):
        extra = ""
        if r.get("planned") is not None and r["planned"] != r.get("n"):
            extra = f" of {r['planned']} planned"
        if r.get("degraded"):
            extra += " (DEGRADED: json unparseable, fell back to the text log)"
        print(f"  {r['step']:10} {r.get('n', 0)}{extra}")
    for r in of("step_skipped"):
        print(f"  {r['step']:10} skipped")

    errs = of("tool_error")
    print(f"  {'errors':10} {len(errs)}")
    for r in errs:
        print(f"      {r['tool']}: {r['msg'][:110]}")
    for r in of("trunc"):
        print(f"      truncated: {r['what']}")

    exposed = [r for r in of("listen") if r["addr"] not in ("127.0.0.1", "::1")
               and not r["addr"].startswith("127.")]
    if exposed:
        print("  listeners on routable addresses (the manager decides which are unexpected):")
        for r in sorted(exposed, key=lambda x: (x["proto"], x["port"])):
            print(f"      {r['proto']}/{r['port']:<6} {r['addr']:<24} {r['process']}")

    lm = of("lynis_meta")
    if lm:
        sev = collections.Counter(r["severity"] for r in of("lynis"))
        pk = (of("packages") or [{}])[0].get("vulnerable")
        print(f"  lynis      hardening index {lm[0]['hardening_index']}, "
              f"{sev.get('warning', 0)} warnings, {sev.get('suggestion', 0)} suggestions, "
              f"{pk} vulnerable packages")
    bm = of("bench_meta")
    if bm:
        print(f"  docker-bench score {bm[0].get('score')}, {len(of('bench'))} failures "
              f"of {bm[0].get('checks')} checks")


    scans = of("scan_ok")
    if scans:
        print("  perimeter cross-scan:")
        for s in scans:
            ports = [p["port"] for p in of("port") if p["target"] == s["target"]]
            note = ""
            if s["target"].endswith("_mesh"):
                note = ("  <- EXPECTED: the ACL has no app-host -> manager rule. Anything open "
                        "here is an ACL regression to fix in acl.hujson, never a baseline entry."
                        if not ports else
                        "  <- ACL REGRESSION: this should have been empty")
            print(f"      {s['target']:16} {s['ip']:18} open: {sorted(ports) or 'none'}{note}")
    return 0

USAGE = """usage: run.py [--summary | --force-unmanaged]

  (no arguments)      run the audit. Must be started by systemd:
                        systemctl start secaudit-host.service
  --summary           print a digest of the last report. Read-only, no privileges needed.
  --force-unmanaged   run the audit OUTSIDE the unit, without its cgroup caps or filesystem
                      containment. For debugging only, on a machine you can afford to lose.
"""


def main():
    args = sys.argv[1:]
    # Reject anything unrecognised instead of ignoring it. An unknown flag used to fall through to
    # "run the whole audit as root", which is how a mistyped `--summary` against an older copy of
    # this script started an unmanaged full run on the manager on 2026-09-06. A heavyweight root
    # operation must never be the default outcome of a typo.
    unknown = [a for a in args if a not in ("--summary", "--force-unmanaged", "-h", "--help")]
    if unknown or "-h" in args or "--help" in args:
        print(USAGE, file=sys.stderr)
        if unknown:
            print(f"unrecognised argument(s): {' '.join(unknown)}", file=sys.stderr)
            return 2
        return 0

    # --summary is read-only and needs no privileges; everything else does.
    if "--summary" in args:
        return summarise()
    if os.geteuid() != 0:
        print("secaudit run.py must run as root", file=sys.stderr)
        return 2
    # systemd sets INVOCATION_ID for every unit it starts. Without it we are outside the unit, which
    # means no MemoryMax, no CPUQuota and no ProtectSystem — the combination that OOM-killed
    # VictoriaMetrics and took the manager down. Refuse rather than trust the operator to remember.
    if not os.environ.get("INVOCATION_ID") and "--force-unmanaged" not in args:
        print("refusing to run outside systemd: the unit carries the memory cap and the filesystem\n"
              "containment, and a bare run has neither. Use:\n"
              "  systemctl start secaudit-host.service\n"
              "Override only if you know why: run.py --force-unmanaged", file=sys.stderr)
        return 2
    for d in (STATE, LOGDIR, os.path.join(STATE, "trigger.d")):
        os.makedirs(d, exist_ok=True)
    # Consume the on-demand trigger FIRST, so a run started by the .path unit cannot loop.
    try:
        os.path.exists(TRIGGER) and os.remove(TRIGGER)
    except OSError:
        pass

    global _runid, _t0
    _runid = "%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), os.urandom(3).hex())
    _t0 = time.time()
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    emit(k="meta", runid=_runid, ts=int(_t0), host=os.uname().nodename, schema=1)

    for name, fn in (("listeners", step_listeners), ("lynis", step_lynis),
                     ("bench", step_bench), ("perimeter", step_perimeter)):
        if STEPS and name not in STEPS:
            emit(k="step_skipped", step=name)   # visible, so a partial run is never mistaken for
            continue                            # a clean one
        try:
            fn()
        except Exception as e:                      # noqa: BLE001 — one broken step must not
            tool_error(name, f"unhandled: {e}")     # cost us the other four
        write_report(complete=False)                # checkpoint: a kill now loses one step, not all
    for t in _truncated:
        emit(k="trunc", what=t)

    write_report(complete=True)
    print(f"secaudit {_runid}: {len(_records) + 1} records in {time.time() - _t0:.0f}s "
          f"-> {os.path.join(STATE, 'report.ndjson')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
