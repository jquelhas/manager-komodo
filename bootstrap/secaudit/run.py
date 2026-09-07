#!/usr/bin/env python3
"""secaudit host bundle — the audit that has to run ON the machine.

Runs as root from secaudit-host.service and writes ONE NDJSON file to
$SECAUDIT_STATE/report.ndjson. Everything here is read-only auditing: it inspects, it never
installs, reconfigures, restarts or removes anything. The only paths it writes are
$SECAUDIT_STATE, $SECAUDIT_CACHE and $SECAUDIT_LOG, and the systemd unit enforces that with
ProtectSystem=strict + ReadWritePaths — so this is a kernel guarantee, not a promise from a script.

THIS FILE RUNS AS ROOT. It is the most review-sensitive file in the repo. It therefore:
  - reads nothing from outside $SECAUDIT_ROOT,
  - takes no network parameters (the only outbound traffic is trivy's vulnerability DB and, on the
    designated host, an nmap of addresses fixed in the unit's environment),
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
3.8 GB manager OOM-killed VictoriaMetrics and took the host down. The trivy step now enforces its
own floor and ceiling so the damage is bounded either way, but the unit is still the way in.
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
CACHE = os.environ.get("SECAUDIT_CACHE", "/var/cache/secaudit")
LOGDIR = os.environ.get("SECAUDIT_LOG", "/var/log/secaudit")
TRIGGER = os.path.join(STATE, "trigger.d", "run")

# Caps. Detail lines are for the archive on the manager; the metrics only ever use the summaries,
# so truncating detail costs nothing that alerts depend on — and it is reported when it happens.
MAX_IMAGES = int(os.environ.get("SECAUDIT_MAX_IMAGES", "40"))
MAX_VULN_LINES = int(os.environ.get("SECAUDIT_MAX_VULN_LINES", "600"))
TRIVY_SEVERITY = os.environ.get("SECAUDIT_TRIVY_SEVERITY", "HIGH,CRITICAL")
# Memory floor and ceiling for the trivy step. The floor stops it starting on a machine that is
# already tight; the ceiling stops it growing into one.
TRIVY_MIN_FREE_MB = int(os.environ.get("SECAUDIT_TRIVY_MIN_FREE_MB", "1024"))
TRIVY_MEM_LIMIT_MB = int(os.environ.get("SECAUDIT_TRIVY_MEM_LIMIT_MB", "512"))
# Java handling: "skip" (default) or "full".
#   skip  Java archives are excluded from analysis, so trivy never needs its Java index DB — a
#         ~1 GB download per host. Cost: NO Java/JAR vulnerabilities are reported. That gap is
#         published as a metric (secaudit_trivy_java_skipped) rather than left silent, because an
#         unreported gap in a vulnerability scanner is worse than a known one.
#   full  Correct but expensive: trivy downloads the Java index DB the first time it meets a JAR.
# Not a theoretical choice: ankane/pghero on the manager bundles JARs, and with the Java DB absent
# trivy does not degrade — it FAILS the whole image scan.
TRIVY_JAVA = os.environ.get("SECAUDIT_TRIVY_JAVA", "skip").strip().lower()
_JAVA_GLOBS = "**/*.jar,**/*.war,**/*.ear,**/*.par"
# Addresses to scan from here, "name=ip" separated by spaces. Set only on the designated
# cross-scan host; empty everywhere else.
PERIMETER_TARGETS = os.environ.get("SECAUDIT_PERIMETER_TARGETS", "").strip()
PERIMETER_PORTS = os.environ.get(
    "SECAUDIT_PERIMETER_PORTS", "1-1024,3000,5432,8120,8428,8880,9093,9120,9187,60022")
PERIMETER_MAX_RATE = os.environ.get("SECAUDIT_PERIMETER_MAX_RATE", "100")

TIMEOUTS = {"listeners": 60, "lynis": 900, "bench": 600, "trivy": 1800, "perimeter": 900}
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
# 4. Trivy — CVEs in the images ALREADY on this host. No registry pull: that is the whole reason
# this runs here instead of centrally, and it is also the only way to see host-built images
# (gimsv2-backend:latest, segcore-site:current) which exist in no registry.
#
# The DB is refreshed once per run and then every scan uses --skip-db-update, so an upstream
# rotation mid-run cannot make the results inconsistent. Never --skip-db-update WITHOUT a refresh
# path: a stale DB produces silent false negatives, the worst failure a vulnerability scanner has,
# because the dashboard goes green. Hence secaudit_trivy_db_age_seconds and its alert.
# --------------------------------------------------------------------------------------------
def _trivy_db_age():
    meta = os.path.join(CACHE, "trivy", "db", "metadata.json")
    try:
        with open(meta, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        for key in ("UpdatedAt", "DownloadedAt"):
            v = doc.get(key)
            if v:
                t = time.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S")
                import calendar
                return max(0, int(time.time() - calendar.timegm(t)))
    except (OSError, ValueError, KeyError):
        pass
    try:
        return max(0, int(time.time() - os.stat(meta).st_mtime))
    except OSError:
        return None


def _available_mb():
    """MemAvailable in MiB, or None if it cannot be read."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def step_trivy():
    trivy = os.path.join(ROOT, "bin", "trivy")
    if not os.path.exists(trivy):
        return tool_error("trivy", "not installed")

    # Trivy is by far the heaviest step, and on a small control plane it is the one that can hurt
    # the machine it is auditing. On 2026-09-06 an unbounded manual run of this script OOM-killed
    # VictoriaMetrics on the 3.8 GB manager and took the host down with it. The systemd unit caps
    # it (MemoryMax=1G), but a script must not depend on how it was invoked for that: these two
    # guards make the cap intrinsic.
    avail = _available_mb()
    if avail is not None and avail < TRIVY_MIN_FREE_MB:
        return tool_error("trivy", f"skipped: only {avail}MiB available, need {TRIVY_MIN_FREE_MB}MiB "
                                   f"(set SECAUDIT_TRIVY_MIN_FREE_MB to override)")
    # GOMEMLIMIT is the right lever for a Go binary: it makes the GC work harder as it approaches
    # the ceiling instead of growing the heap. RLIMIT_AS would be wrong here — the Go runtime
    # reserves large virtual address ranges and would die spuriously.
    tenv = dict(os.environ, GOMEMLIMIT=f"{TRIVY_MEM_LIMIT_MB}MiB", GOGC="50")

    cachedir = os.path.join(CACHE, "trivy")
    os.makedirs(cachedir, exist_ok=True)
    base = [trivy, "image", "--cache-dir", cachedir, "--scanners", "vuln",
            "--quiet", "--parallel", "1"]
    if TRIVY_JAVA != "full":
        base += ["--skip-java-db-update", "--skip-files", _JAVA_GLOBS]
    emit(k="trivy_policy", java=("full" if TRIVY_JAVA == "full" else "skipped"))

    rc, _o, err = run(base + ["--download-db-only"], 900, env=tenv)
    if rc != 0:
        tool_error("trivy-db", err or f"rc={rc}")   # non-fatal: an older DB still finds most CVEs
    age = _trivy_db_age()
    if age is not None:
        emit(k="trivy_db", age_seconds=age)

    # Which images actually back a running container. Without this distinction an image nobody
    # runs — mongo:8.0 is still on the manager from before the move to FerretDB, with 272 fixable
    # CVEs — would alert forever about surface that does not exist. It is still scanned and still
    # reported; it is just not the same finding as a CVE in something serving traffic.
    in_use = set()
    rc, out, _e = run(["docker", "ps", "--format", "{{.Image}}"], 60)
    if rc == 0:
        in_use = {x.strip() for x in out.splitlines() if x.strip()}

    rc, out, err = run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}",
                        "--filter", "dangling=false"], 60)
    if rc != 0:
        return tool_error("docker", err or f"rc={rc}")
    images = []
    seen = set()
    for line in out.splitlines():
        ref, _, iid = line.partition("\t")
        if not ref or ref.endswith(":<none>") or ref.startswith("<none>") or ref in seen:
            continue
        seen.add(ref)
        images.append((ref, iid))
    images.sort()
    images.sort(key=lambda t: t[0] not in in_use)   # running images first; the budget cuts the rest
    all_images = list(images)
    # ROTATE the starting point between runs. Sorting alone is deterministic, which sounds good
    # until a step budget cuts the list at the same place every night: the tail of the alphabet
    # would then never be scanned, permanently and silently. A persisted cursor guarantees every
    # image is reached within a few runs, and the ones missed this time are reported below so the
    # coverage gap is visible rather than assumed away.
    cursor_file = os.path.join(STATE, "trivy-cursor")
    start = 0
    if images:
        try:
            with open(cursor_file, "r", encoding="utf-8") as fh:
                start = int(fh.read().strip()) % len(images)
        except (OSError, ValueError):
            start = 0
    images = images[start:] + images[:start]
    if len(images) > MAX_IMAGES:
        _truncated.append("images")
        images = images[:MAX_IMAGES]

    vuln_lines = 0
    g_done = []
    step_start = time.time()
    for ref, iid in images:
        # Budget the STEP, not just each image. On the manager, 26 images throttled at MemoryHigh
        # took longer than the unit's whole timeout, and being SIGTERMed mid-scan is a worse
        # outcome than scanning fewer images and saying so.
        if time.time() - step_start > TIMEOUTS["trivy"]:
            if "images_time" not in _truncated:
                _truncated.append("images_time")
            emit(k="tool_error", tool="trivy",
                 msg=f"step budget of {TIMEOUTS['trivy']}s reached; {len(images) - len(g_done)} "
                     f"image(s) not scanned")
            break
        g_done.append(ref)
        rc, out, err = run(base + ["--skip-db-update", "--severity", TRIVY_SEVERITY,
                                   "--format", "json", ref], 600, env=tenv)
        if rc != 0:
            emit(k="image", image=ref, id=iid, ok=False)
            tool_error("trivy", f"{ref}: {(err or '')[:200]}")
            continue
        try:
            doc = json.loads(out or "{}")
        except ValueError as e:
            emit(k="image", image=ref, id=iid, ok=False)
            tool_error("trivy", f"{ref}: unparseable json ({e})")
            continue
        counts = {}
        for result in doc.get("Results") or []:
            for v in result.get("Vulnerabilities") or []:
                sev = str(v.get("Severity", "UNKNOWN")).upper()
                fixed = bool(v.get("FixedVersion"))
                counts[(sev, fixed)] = counts.get((sev, fixed), 0) + 1
                if vuln_lines < MAX_VULN_LINES:
                    emit(k="vuln", image=ref, id=str(v.get("VulnerabilityID", "")),
                         pkg=str(v.get("PkgName", "")), sev=sev,
                         inst=str(v.get("InstalledVersion", ""))[:40],
                         fix=str(v.get("FixedVersion", ""))[:40])
                    vuln_lines += 1
                elif "vulns" not in _truncated:
                    _truncated.append("vulns")
        emit(k="image", image=ref, id=iid, ok=True, in_use=ref in in_use,
             counts=[{"sev": s, "fixable": f, "n": n} for (s, f), n in sorted(counts.items())])
    for ref, _iid in images:
        if ref not in g_done:
            emit(k="image_skipped", image=ref)      # visible coverage gap, not a silent one
    try:
        with open(cursor_file, "w", encoding="utf-8") as fh:
            fh.write(str((start + len(g_done)) % max(1, len(all_images))))
        os.chmod(cursor_file, 0o600)
    except OSError:
        pass
    emit(k="step_ok", step="trivy", n=len(g_done), planned=len(images))


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

    imgs = of("image")
    if imgs:
        ok = [i for i in imgs if i.get("ok")]
        cr = sum(c["n"] for i in ok for c in (i.get("counts") or [])
                 if c["sev"] == "CRITICAL" and c["fixable"])
        hi = sum(c["n"] for i in ok for c in (i.get("counts") or [])
                 if c["sev"] == "HIGH" and c["fixable"])
        print(f"  trivy      {len(ok)}/{len(imgs)} images scanned, {len(of('image_skipped'))} left "
              f"for the next run | fixable: {cr} CRITICAL, {hi} HIGH")
        worst = sorted(ok, key=lambda i: -sum(c["n"] for c in (i.get("counts") or []) if c["fixable"]))
        for i in worst[:3]:
            n = sum(c["n"] for c in (i.get("counts") or []) if c["fixable"])
            if n:
                print(f"      {i['image'][:52]:54} {n} fixable")

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
    for d in (STATE, CACHE, LOGDIR, os.path.join(STATE, "trigger.d")):
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
                     ("bench", step_bench), ("trivy", step_trivy),
                     ("perimeter", step_perimeter)):
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
