# Fleet security auditor (`secaudit`) — design and plan

> Status: phase 1 implemented and verified in production on 2026-09-04. Phases 2-5 planned, not
> built. Each phase below is marked. The `manager-security-fast.timer` unit is versioned but, as
> with `manager-backup`, installing and enabling it is a manual step — see
> [../SECURITY-AUDIT.md](../SECURITY-AUDIT.md).
> This document is the decision record: which tools, why these and not others, why native and not
> containerized, why policy is evaluated at scrape time. `DESIGN.md` shows the cost of not keeping
> such a record — it describes things that were never built and asserts a firewall that does not
> exist. Keep this file honest about what *is*.

## Why

The manager orchestrates a fleet of app hosts and exposes `komodo.segcore.eu` itself. Before this,
the repo had **no audit tooling at all**: no scanner, no SBOM, no CI, no verification job. The
security posture is architectural (socket-proxy, `read_only`, deny-by-default ACL, path-scoped
`/provisioning`) and *documented*, but was never *measured*. Two consequences, both verified:

- `DESIGN.md` claims nftables on the manager closes everything but 443/41641 and that sshd binds
  `100.64.0.1:22`. Reality: `ufw` is `ENABLED=no`/`inactive`, there is no host INPUT policy, and
  sshd listens on `0.0.0.0:60022`. The external (OVH) firewall is the authoritative gate — that is
  the correct, recorded decision — but **nothing verified that its allowlist is still
  443/tcp + 41641/udp + 60022/tcp**.
- The 5-step checklist to expose an internal service (labels → `dns.extra_records` → step-ca
  `extra_hosts` → Homepage → `.env`) is manual, and one missed step stalls the **entire** internal
  ACME renewal queue. That was the root cause of the 2026-08-23 outage.

Goal: turn the documented posture into **metrics with alerts**, covering public open ports, TLS
configuration and certificate validity, web vulnerabilities on public interfaces, mesh-side
exposure drift, image CVEs and Docker/CIS hardening — reusing the existing observability path
(VictoriaMetrics → vmalert → Alertmanager → e-mail + Grafana), adding no new service with a UI.

## Tool choice

Two groups, split by **where the answer exists**.

**A. Audit from inside — installed natively on every machine, manager included.** These inspect the
OS: `/etc`, packages, kernel, sysctl, accounts, the Docker daemon, local images. In a container they
would inspect the container. None is a daemon: each is a shell script or a single binary, costs
nothing at rest, and runs for 1-3 minutes a day.

| Tool | Form | Role |
|---|---|---|
| `lynis` | upstream tarball (CISOfy), version + SHA-256 pinned | OS hardening: sshd, sysctl/kernel, permissions, accounts, auth policy, pending security updates, banners |
| `docker-bench-security` | upstream tarball `v1.6.1`, SHA-256 pinned | CIS Docker Benchmark: daemon config, privileged containers, exposed `docker.sock`, images without a user, restart policies. **Caveat, corrected 2026-09-06:** v1.6.1 was released 2023-12-20, not 2026-06-04 — that date is the repo's last *commit*, which an earlier draft of this document conflated with the release. Upstream is maintained but slow: the encoded benchmark is CIS 1.6.0 against Docker 29.6.1 here, so some checks are dated. Still far better than the 2019 Docker Hub image, and the per-section budget design (alert on regression, not on absolute count) is what makes dated checks tolerable. |
| `trivy` | single release binary, version + SHA-256 pinned | CVEs in **local** images, including host-built ones (`gimsv2-backend:latest`, `segcore-site:current`) |
| `ss` (iproute2, already present) | — | socket and bind-address enumeration, with process attribution (runs as root) |
| `nmap` (apt, only on the cross-scan host) | — | the manager's public perimeter, seen from outside |

**B. Audit from outside — ephemeral containers on the manager.** These measure what is only visible
externally, need no privileges and leave nothing installed: `nmap`
(`instrumentisto/nmap`), `testssl.sh` (`drwetter/testssl.sh`), `nuclei`
(`projectdiscovery/nuclei`), all pinned.

Rejected, with reasons:

- **OpenVAS/GVM** — needs ~4-8 GB RAM and ~10 GB for the feed alone. The manager has 2 vCPU /
  3.8 GB / 14 GB free, shared with VictoriaMetrics and Komodo. Out of the question.
- **`docker/docker-bench-security:latest`** — last pushed 2019, encodes CIS ~1.13 against Docker 29.
  It produces confidently wrong findings, which is worse than no findings. Containerizing it was
  also unnecessary: upstream is a shell script you install.
- **Lynis in a container** — would audit the container. Worthless.
- **`docker.sock` mounted into a third-party image** (how trivy and bench were going to run on the
  hosts). Native installation removes this entirely: the scan is done by a pinned artifact running
  as the host's root, not by an external image handed a root-equivalent API. **This is the single
  biggest security improvement of the native design.**
- **ZAP / Wazuh** — ZAP only pays off with authenticated flows; Wazuh is a full SIEM.
- **Home-grown scanners** — only for what is specific to this repo: target discovery, baseline
  comparison, internal-checklist drift, and normalization into metrics.

## Architecture

### Three perspectives, and why all three are needed

There is no host firewall, so a socket bound to `0.0.0.0` is **not** necessarily exposed — the
external firewall decides, and it is invisible from inside. Therefore:

- `perspective="local"` — **what is bound**. Cheap, every 5 minutes. A stray `-p 5432:5432` shows up
  in minutes. Does not measure exposure.
- `perspective="public"` — **what the external firewall lets through**. The only measurement of the
  real perimeter. The cross-scan from an app host is the only way to verify the manager's own
  external allowlist.
- `perspective="mesh"` — **measures the Headscale ACL**, not the host's listeners. An unexpected
  open port here is an `acl.hujson` regression, which is a serious finding in its own right, but it
  is not bind drift.

Conflating the three is the easiest way to build false confidence. The dashboard and the runbook
must say so.

### Where things run

**Orchestrator: scripts in `scripts/` driven by systemd timers in `scripts/systemd/`** — exactly the
`backup-manager.sh` + `manager-backup.{service,timer}` pattern, which already does
`docker run --rm --network manager-komodo ...`. No new mechanism. A permanent auditor container was
rejected: it would need **write** access to `docker.sock`, i.e. a root-equivalent, always-on
container on the same network as Komodo Core and FerretDB — a larger, permanent version of the
surface the socket-proxy exists to refuse.

Note: `CPUQuota=`/`MemoryMax=` on a unit do **not** constrain `docker run` workloads (they land in
dockerd's cgroup). Manager-side limits go on the `docker run` invocation; the native host bundle is a
direct child of its unit, so there the cgroup limits do work.

**On the hosts: a native bundle plus one timer, and a courier container only for collection.**
`/opt/secaudit/` holds lynis, docker-bench and trivy, each pinned by version and SHA-256, driven by
one `secaudit-host.timer`. `run.sh` runs as root and writes a single NDJSON to
`/var/lib/secaudit/report.ndjson` (atomic, tmp + `mv`): socket enumeration, lynis, docker-bench,
trivy, and on the designated host an nmap of the manager's public IP and mesh IP.

**The host emits raw facts; policy is applied on the manager**, which already knows each host's mesh
IP and `PUBLIC_BIND_IP`. Changing policy never means touching a host.

**Collection uses a zero-privilege courier Deployment.** Komodo has no arbitrary command execution
over its API (the `execute/*` variants are Deployment/Repo/Build/Procedure/Action only), but a
Deployment runs a container and `read/SearchDeploymentLog` runs `grep` on the host and returns
stdout. That is enough: `secaudit-collect-<host>` is `alpine` with `--entrypoint /bin/cat`,
`network: none`, `--cap-drop ALL --read-only`, `/var/lib/secaudit:/r:ro`, `command: /r/report.ndjson`.
No network, no capabilities, no `docker.sock`, no listening port, **no Headscale ACL change** — the
transport is Core → periphery `:8120`, already open.

**Installation and updates.** `bootstrap/onboard-host.sh` already runs as root, is apt-based and
enables systemd units, so it gains a step that installs the bundle — new hosts are covered at
onboarding. For already-onboarded hosts and for scanner version bumps,
`bootstrap/install-secaudit.sh` (idempotent) runs over **SSH break-glass on 60022**, which is
precisely the mechanism `onboard-host.sh` already designates for root OS operations.

**The "no agents on hosts" rule is honoured where it matters.** No daemon, no permanently privileged
process, no new listening port, no new credential distributed. There is a package and a timer, which
is exactly how Lynis is designed to be used. What is given up is the literal reading ("nothing
installed"); what is gained is real fidelity and the removal of `docker.sock` from third-party hands.

**Do not use `POST /terminal/execute`.** It exists on Core (absent from the OpenAPI paths because it
streams) and gives a root-equivalent shell on any host to anyone holding `KOMODO_API_KEY`. It has no
exit code, no retrievable log and no declarative record of what ran — the audit itself would be
unauditable. Recorded as a finding to decide separately (periphery supports disabling terminals;
`onboard-host.sh` does not).

### Data flow

```
every machine (manager + hosts):
  secaudit-host.timer -> /opt/secaudit/run.sh (root)
        ss+ip · lynis · docker-bench · trivy [· nmap on the cross-scan host]
        -> /var/lib/secaudit/report.ndjson    (raw facts, no policy)

manager: manager-security-*.timer -> scripts/security-*.sh
  |- reads its own /var/lib/secaudit/report.ndjson
  |- per host: execute/Deploy secaudit-collect-<host> -> poll InspectDeploymentContainer
  |            -> read/SearchDeploymentLog             (grep runs on the host)
  \- docker run --rm: nmap -> public and mesh IPs · testssl · nuclei
        -> normalize + atomic write (tmp + mv) into security/state/

provisioning (read_only, ./security:/security:ro) -> GET /metrics/security
        -> VictoriaMetrics job 'security' (60s) -> vmalert -> Alertmanager (e-mail) + Grafana
```

**Policy is evaluated at scrape time, not scan time.** The exporter in `provisioning/server.py`
reads raw state and applies baseline + suppressions on every scrape (60s), using `tomllib` and
`fnmatch` (both stdlib — this preserves the container's "python:3.13-slim, stdlib only, read-only
rootfs" property). Consequence: editing the baseline or letting a suppression lapse takes effect at
the next scrape, not at the next weekly scan.

**State lives in `security/state/`, mounted `:ro`, not in `provisioning/store/`.** The store has a
reaper thread that `rmtree`s entries by `meta.json.expires_at`, and "ephemeral capability where the
uuid is the secret" semantics. Writing state as `ubuntu` and mounting it read-only also buys a
better property: **the only publicly-routed process in the stack cannot forge or erase audit
results.** Mount the directory, not individual files, so atomic `mv` does not break inodes.

## Configuration

Five surfaces, each with one owner. The rule is: **no policy in code, no secrets in a policy file.**

| File | Contents | Read by | Effect of an edit |
|---|---|---|---|
| `.env` (`SECAUDIT_*` block) | deployment parameters: on/off, cross-scan host, nmap/nuclei rate limits, severities, resource caps, retention days, disk guard | `security-*.sh`, via `env_get` | next timer run (or immediately via `secaudit.sh run`) |
| `security/baseline/ports.toml` | expected ports per role and perspective | the exporter, **at scrape** | <= 60s, no re-scan |
| `security/baseline/bench.toml` | per-section budgets for docker-bench and Lynis | the exporter, at scrape | <= 60s, no re-scan |
| `security/suppressions.toml` | accepted findings, `expires` mandatory | the exporter, at scrape | <= 60s, no re-scan |
| `bootstrap/secaudit/versions.env` | version + SHA-256 of lynis, docker-bench, trivy | `install-secaudit.sh`, on each machine | only when the installer runs again (SSH) |
| `docker/vmalert/rules/security/*.yml` | alert thresholds and severities | vmalert | 30s (hot reload) |

No new secret: `KOMODO_API_KEY`/`SECRET` already exist and are the only credential needed.
`secaudit.sh baseline-init` generates the first budget set from what was observed, for the initial
commit — the step that makes the first e-mail useful instead of a wall of Lynis warnings.

## On-demand execution

Scheduled is the normal mode; **on demand is the working mode**, and is what every test uses.

```
secaudit.sh run all|fast|ports|tls|web|host|collect [--host <name>] [--dry-run]
secaudit.sh status                 # last run, status and age per scan and host
secaudit.sh show ports|tls|vulns|lynis|bench [--host <name>]
secaudit.sh baseline-init          # write observed budgets, for review and commit
secaudit.sh install --host <name>  # print (or run) the SSH install/update command
```

`--dry-run` prints the exact `docker run` commands and API calls and executes nothing. It is the
first command to run against a new host.

**Triggering a host audit from the manager, without SSH and without root exec** (phase 2): besides
the timer, `run.sh` is started by a `.path` unit watching
`/var/lib/secaudit/trigger.d/run`. The manager deploys a second courier,
`secaudit-trigger-<host>`, whose only job is `touch /t/run` — no network, no capabilities, and the
only writable path is a subdirectory holding sentinel files, **never `report.ndjson`**, which the
collect courier mounts `:ro`. The worst an abuse of that path achieves is requesting an audit.
`run.sh` deletes the sentinel on start so it cannot loop.

From the Komodo UI, free of extra code: *Deploy* on `secaudit-trigger-<host>` audits that host, and
*Deploy* on `secaudit-collect-<host>` shows the raw result in the Komodo log.

## Non-destructiveness guarantees

Three of these tools run as root on production machines. The guarantees are of four kinds, in
increasing strength.

**1. None of the tools changes state, by nature.** What each writes, and nothing else:

| Tool | Writes | Never does |
|---|---|---|
| `ss`, `ip` | nothing | — |
| `lynis audit system` | its report and log under `/var/log/secaudit/` | does not change sysctl, sshd, accounts or permissions; installs and removes nothing |
| `docker-bench-security` | its log under `/var/log/secaudit/` | only `docker inspect`/`info`/`ps`; no container lifecycle operation |
| `trivy image` | its cache under `/var/cache/secaudit/trivy` | no pull; does not modify or remove images |
| `nmap -sT` | stdout | connect scan, no raw sockets; no `-sU`, no intrusive NSE |

Explicitly **outside** `run.sh`: no `apt-get update`/`upgrade` (the pending-security-update count
reads the apt metadata already on disk — refreshing the index is a state change and an operator
decision, never an audit side effect), no `systemctl restart`, no writes to `/etc`, no Docker
configuration change, no container operations.

**2. Containment is enforced by the kernel, not promised by the script.** `secaudit-host.service`
carries systemd hardening, which turns "the script does not write there" into "the script *cannot*":

```ini
ProtectSystem=strict          # whole filesystem read-only except the paths below
ReadWritePaths=/var/lib/secaudit /var/cache/secaudit /var/log/secaudit
ProtectHome=yes  PrivateTmp=yes  NoNewPrivileges=yes  ProtectKernelTunables=yes
MemoryMax=1G  MemoryHigh=768M  CPUQuota=100%  Nice=10  IOSchedulingClass=idle
TimeoutStartSec=1800
```

With `ProtectSystem=strict`, `/etc` and `/usr` are read-only to the audit even as root, even with a
bug in `run.sh`. **To verify in phase 2:** Docker socket access under `ProtectSystem=strict`
(`connect()` to an AF_UNIX socket needs write permission on the inode); the expected fix is adding
`/run/docker.sock` to `ReadWritePaths`, falling back to `ProtectSystem=full`. Confirm empirically,
do not assume.

**3. The one destructive operation in the whole design is isolated and asserted.**
`execute/Deploy` removes and recreates the container **with that name**. If an audit Deployment were
created with a name colliding with a real container, Deploy would remove it. So
`setup-secaudit.sh`, before creating each Deployment:

- asserts the name matches `^secaudit-(collect|trigger)-`;
- calls `read/ListDockerContainers` on the server and **aborts** if a container with that name
  already exists;
- never sets `custom_name` (the container name is the resource name);
- asserts `network: "none"` in the echo-check — the Komodo schema defaults `network` to `host`, and
  omitting the field would hand the couriers the host netns for no reason.

An assertion in code, not a comment in a plan, because it is the only path by which this system
could delete anything.

**4. Rollout order and reversibility.** Manager first (the system already being changed), then
`segcore-demo` (no real tenants), then `segcore-host1`. On each host: `--dry-run`, then a manual
`systemctl start secaudit-host.service` watched live, and only then
`systemctl enable --now secaudit-host.timer`. The timer is the last step, never the first.

Full rollback in two commands, and complete *by construction* because nothing outside the
`secaudit` paths was ever touched: `install-secaudit.sh --uninstall` on the host and
`setup-secaudit.sh --destroy` on the manager.

**No service goes down, for a structural reason:** nothing here stops, restarts or reconfigures
anything. Contrast `backup-manager.sh`, which **stops** step-ca, grafana and komodo-core at 04:00 —
the only component in the repo with a downtime window, and the auditor is scheduled to avoid it
(01:00-03:30 plus the `sec_require_no_backup` guard). The only risk is load, not availability.

`nuclei` is the honest exception: it is the only tool generating traffic against the application. It
touches no host OS — it speaks HTTPS to the app — but it is last in the phase order, runs with safe
templates only (`-exclude-tags intrusive,dos,fuzz,brute-force`, no DAST), rate-limited, against
`segcore-demo` first, and wrapped in an Alertmanager silence so scan traffic does not trip
`SegcoreHigh5xxRate`.

## Resource budget and retention

Measured, not guessed:

| | manager | `segcore-demo` | `segcore-host1` |
|---|---|---|---|
| CPU | 2 vCPU | 4 | 8 |
| RAM total / used | 3.8 GB / 2.5 (1.3 available) | 31.3 GB / 2.0 | 22.9 GB / 2.2 |
| Free disk | **14 GB** | 79 GB (108 total) | 160 GB (193 total) |
| Local images | — | 11, 4.0 GB | 9, 3.6 GB |

Cost per run (once a day, ~10 minutes total): `ss`/`ip` negligible; lynis 1-3 min, ~50 MB;
docker-bench 1-2 min, ~50 MB; trivy 3-6 min with a warm DB, **300-800 MB peak**, `--parallel 1`;
nmap cross-scan 1-3 min, ~30 MB.

On the hosts this is noise: one core out of 4 or 8, ~800 MB peak against 29 GB and 20 GB of free
RAM, with `Nice=10` and `IOSchedulingClass=idle` so trivy's I/O does not compete with Postgres.
**The manager is the tight machine** — 1.3 GB available RAM against trivy's 800 MB peak. Hence
`MemoryMax=1G` with `MemoryHigh=768M`: if trivy overruns, trivy is throttled and ultimately
cgroup-OOM-killed, not VictoriaMetrics or Komodo. A killed trivy emits `{"k":"tool_error"}` →
`secaudit_scan_last_status 0` → alert. **The auditor failing is a metric; never an outage elsewhere.**

Steady-state disk: pinned binaries `/opt/secaudit` ~80 MB (fixed); trivy DB cache
`/var/cache/secaudit/trivy` ~1 GB unpacked (~116 MB download), fixed, and `--skip-java-db-update`
prevents the 961 MB java-db; `report.ndjson` 100-500 KB **overwritten** each run, not accumulated;
tool logs ~1 MB, truncated at the start of each run plus a logrotate drop-in; nuclei templates
~300 MB on the manager (cache refreshed, not accumulated); historical NDJSON archive ~200 KB per run
gzipped, pruned by `SECAUDIT_RETENTION_DAYS=90` → ~55 MB for three machines.

Manager total ~1.4 GB of 14 GB free, and the `sec_require_free_disk` guard makes a scan **skip with a
metric** rather than fill the disk.

**Logging does not grow without bound**, via three distinct mechanisms:

1. **On the hosts** the report and tool logs are *overwritten*, not appended. `run.sh` writes the
   NDJSON to a **file**, never to stdout: to stdout it would land in the journal every single day.
   The unit's journal keeps a handful of status lines.
2. **The courier's container log** holds the NDJSON — that is what gets harvested. Doubly bounded:
   `--log-opt max-size=8m --log-opt max-file=2` in `extra_args` (these hosts' containers have no
   rotation configured, so the daemon's unlimited default applies), and `execute/Deploy` removes the
   previous container along with its log, which is already self-limiting.
3. **On the manager** the historical archive is pruned by days and current state is fixed-size.

**Metrics do not grow without bound, and there is a number for it.** VictoriaMetrics holds **8 138
series** and ~343 MB (316 MB storage + 27 MB index) at `-retentionPeriod=60d`, an upper bound of
~60 KB per series over 60 days — pessimistic, because those series are dominated by 10s GIMS
histograms while the security series are near-constant at 60s and compress far better.

Expected count, deliberately bounded by design: lifecycle ~160, listeners and published ports ~75,
ports vs baseline ~60, TLS ~90, image CVEs ~160 (counts by `(host, image, severity, fixable)`,
**never one series per CVE**), Lynis + docker-bench ~210 (warnings only, never PASS), nuclei and
suppressions a few dozen. **~800-1 200 series**, i.e. +10-15% over the current 8 138, ~70 MB worst
case at 60 days.

Three defences against cardinality blow-up: the existing 60-day retention; `_SEC_MAX_SERIES` per
family in the exporter, with `secaudit_findings_truncated{family}` making the cut visible instead of
silent; and the policy rule that per-CVE detail and full URLs live in the on-disk NDJSON, not in the
TSDB. Without the first, one degenerate scan (a misparsed `-p-`, or nuclei with `info` enabled)
writes hundreds of thousands of series into a TSDB with 14 GB of disk.

## Metric contract

Prefix `secaudit_`. `host` is always present (the Komodo Server name, or `manager`), chosen so the
existing Alertmanager `group_by: ['alertname','host','server']` groups per host **with no
Alertmanager change**.

**The invariant that makes alerts behave:** per-finding series are emitted only while the finding
exists (so an alert auto-resolves when a scan clears it); count series are always emitted, 0 when
empty (so dashboards never read `No data` and "clean" is never confused with "exporter broken").

```
# lifecycle (the anti-silent-failure core)
secaudit_scan_last_run_timestamp_seconds{scan,host}
secaudit_scan_last_success_timestamp_seconds{scan,host}
secaudit_scan_last_status{scan,host}          secaudit_scan_duration_seconds{scan,host}
secaudit_scan_max_age_seconds{scan}           secaudit_scan_targets{scan}
secaudit_scan_skipped_total{scan,reason}      secaudit_scan_oom_killed{scan,host}
secaudit_discovery_ok  secaudit_discovery_shrunk  secaudit_target_incomplete{host,field}
secaudit_findings_truncated{family}           secaudit_host_scannable{host}
secaudit_exporter_state_error{file}

# perimeter
secaudit_listener{host,proto,port,bind,scope,process}
secaudit_docker_published_port{host,proto,port,bind,container}
secaudit_port_open{host,target,perspective,proto,port,service,suppressed}
secaudit_port_unexpected{...,suppressed}      secaudit_port_missing{...,suppressed}
secaudit_unexpected_ports{host,target,perspective,suppressed}

# TLS
secaudit_tls_cert_expiry_timestamp_seconds{host,target,port,cn,ca}
secaudit_tls_cert_chain_valid{host,target,port}  secaudit_tls_grade_score{host,target,port}
secaudit_tls_finding{host,target,port,id,severity,suppressed}
secaudit_tls_findings{host,target,port,severity,suppressed}

# web / images / hardening
secaudit_nuclei_finding{host,target,template,severity,path,suppressed}
secaudit_nuclei_findings{host,severity,suppressed}   secaudit_nuclei_templates_loaded
secaudit_image_vulns{host,image,severity,suppressed}
secaudit_image_vulns_fixable{host,image,severity,suppressed}
secaudit_image_scan_status{image}   secaudit_trivy_db_age_seconds{host}
secaudit_bench_failed{host,id,section,suppressed}
secaudit_bench_failures{host,section,suppressed}
secaudit_bench_failures_over_budget{host,section}    secaudit_bench_score{host}
secaudit_lynis_finding{host,test_id,section,severity,detail,suppressed}
secaudit_lynis_findings{host,section,severity,suppressed}
secaudit_lynis_findings_over_budget{host,section,severity}
secaudit_lynis_hardening_index{host}
secaudit_packages_vulnerable{host}
secaudit_internal_name_misconfigured{name,missing}
secaudit_tool_version_info{host,tool,version}
```

Decisions that matter:

- **`ca` ∈ `le|stepca|other` is the most important label in the design.** Internal certificates live
  24h and renew with zero margin. A generic "expires in 21 days" rule would fire permanently on
  every internal endpoint and be muted within a week, taking the useful public-certificate alert
  with it. Splitting on `ca` yields `InternalTlsNotRenewing` at `< 4h`, which catches both
  documented root causes (step-ca down during the renewal window; a dead ACME entry stalling the
  sequential queue) **hours before** every internal UI goes dark at once.
- **Never one series per CVE.** Counts by `(host, image, severity, fixable)` — ~80 series/host.
  Per-CVE detail lives in the on-disk NDJSON.
- **`_fixable` is the metric that alerts.** Alerting on total counts means alerting forever on
  distro CVEs with no fix, and an always-red security stream is worth less than none.
- **`*_over_budget`** = `max(0, failures - budget)`, budget per `(host, section)` in git, applied to
  both docker-bench and Lynis. Both warn about dozens of things nobody will fix on a VPS; alerting
  on the absolute count is guaranteed noise, alerting on regression above a committed budget is a
  ratchet. `lynis_hardening_index` and suggestions are trend-only.
- **`secaudit_packages_vulnerable{host}`** (Lynis `vulnerable_packages_found`) is the most
  actionable finding Lynis brings and existed in no other source. Alerts above 0 with `for: 24h`.
- **Lynis findings are keyed by `(test_id, detail)`, and suggestions are first-class.** Corrected
  2026-09-06 after running the tool: Lynis emits almost everything as `suggestion[]` and almost
  nothing as `warning[]` (41 vs 1 on the manager). An earlier draft alerted on warnings and kept
  suggestions as a trend-only count, which would have missed the substance entirely — including
  the SSH hardening items that motivated this phase. Both are emitted as findings with a
  `severity` label. The `detail` label is required because one test id covers several items:
  `SSH-7408` alone produces six distinct suggestions (`MaxAuthTries`, `AllowTcpForwarding`, ...)
  that would otherwise collapse into a single series.
- **`secaudit_internal_name_misconfigured{name,missing}`** cross-checks live Traefik router `Host()`
  names against `dns.extra_records`, step-ca `extra_hosts` and `services.yaml`.
  `missing` ∈ `dns|stepca_hosts|homepage`. Automates steps 2-4 of the checklist and pre-empts the
  2026-08-23 failure mode.
- **Do not parse `docker/traefik/certs/acme-*.json`** (`root:root 0600`; the scripts run as
  `ubuntu`). The live `ca="stepca"` expiry metric gives the same signal without a sudo grant.

## Baseline and suppressions

`security/baseline/ports.toml` composes explicitly add/remove over a role default, never a silent
merge (full-replace would force every host to restate the defaults, and a default added later would
silently fail to apply). `security/suppressions.toml` is TOML, not YAML: PyYAML would need a
`pip install` inside a `read_only`, stdlib-only container, and that security property is worth more
than YAML's ergonomics.

Fail-closed rules, all in the exporter: `expires` missing, unparseable or already past → the entry
**suppresses nothing** and `secaudit_suppression_invalid` is emitted (an operator who believes they
silenced something and did not is the worst outcome); a horizon cap of
`SECAUDIT_MAX_SUPPRESSION_DAYS=180` kills "expires 2099"; unknown `kind` or missing `reason`/`owner`
→ invalid.

**"Stop alerting without disappearing" is a label, not a filter.** Every finding series carries
`suppressed="0"|"1"` and every count is emitted twice, once per value. Rules filter
`suppressed="0"`; dashboards show both. Nothing is hidden, only reclassified. Plus
`secaudit_suppression_expiry_timestamp_seconds` (alert at 7 days, so renewal is a deliberate
decision) and `secaudit_suppression_stale` (a valid suppression matching no current finding —
dashboard only).

## Alerts

`docker/vmalert/rules/security/security-alerts.yml`, every rule labelled `scope: secaudit`. **No rule
carries `app: segcore`** — `segcore-silence-on.ts` silences on `app="segcore"` for 30 minutes on
every deploy, which would blind the security alerts exactly when a new image lands. Deliberate; do
not "fix" it for consistency.

| Group | Alerts |
|---|---|
| `security_freshness` | `SecurityScanStale` (one rule for every cadence: `(time() - last_success) > on(scan) group_left() secaudit_scan_max_age_seconds`), `SecurityScanFailing`, `SecurityScanTargetsEmpty`, `SecurityDiscoveryDegraded`, `SecurityExporterDown`, `SecurityFindingsTruncated` |
| `security_perimeter` | `UnexpectedPublicListener` (local, 10m, critical), `UnexpectedOpenPortPublic` (15m, critical), `UnexpectedOpenPortMesh` (= ACL regression, warning), `ExpectedPortClosed` |
| `security_tls` | `InternalTlsNotRenewing` (`ca="stepca"` < 4h, critical), `TlsCertExpired`, `PublicTlsCertExpiringSoon` (`ca="le"` < 14d), `TlsWeakConfiguration` |
| `security_web` | `NucleiFindingCritical` (15m), `NucleiFindingHigh` (1h). Medium/low: dashboard only, never e-mail |
| `security_images` | `ImageCriticalVulnFixable` (`for: 6h` — a fixable CVE is a patch task, not an incident), `ImageHighVulnFixableMany` (>10, 24h), `TrivyDbStale` (48h) |
| `security_hardening` | `DockerBenchRegression`, `LynisWarningRegression` (both over-budget), `PendingSecurityUpdates` (`> 0`, `for: 24h`), `InternalNameMisconfigured`, `SecauditToolVersionDrift` |
| `security_hygiene` | `SecuritySuppressionExpiringSoon`, `SecuritySuppressionInvalid` |

`for:` semantics with daily data: between scans the series is constant (rendered from state), so
`for` only delays the first notification; when a scan clears a finding the series **disappears** and
the alert resolves — which is exactly why the "findings absent, counts zero" invariant is not
negotiable.

The Alertmanager child route with `repeat_interval: 24h` is mandatory: under the global
`repeat_interval: 4h`, a persistent finding e-mails every four hours until someone rebuilds, and the
audit ends up in an inbox filter within a week. Security findings are a daily-digest problem, not a
pager problem.

## Pacing and schedule

A `-p-` scan is 65 535 SYNs at one IP: the canonical port-scan signature. Both ends are OVH, and
staying inside OVH's network does not exempt traffic from VAC. Two bad outcomes: the target IP enters
mitigation, so the scan returns garbage **while degrading the manager's real traffic** (Headscale
coordination, onboarding), or an abuse notice arrives. **The structural answer is to do full-range
discovery locally**, where it is free and instant, and leave the external scan only a bounded set to
verify.

| Timer | Cadence | What |
|---|---|---|
| `secaudit-host` (on **every** machine) | daily 01:00 + 30 min jitter | lynis, docker-bench, trivy, listeners, and the cross-scan on the designated host |
| `manager-security-fast` | `*:0/5` | fast sensor: local `ss`+`docker ps`, fleet-wide `read/ListDockerContainers`, internal-checklist drift |
| `manager-security-collect` | daily 01:45 (+ retry 03:15) | harvest each host's `report.ndjson` via the courier |
| `manager-security-ports` | daily 02:10 | top-200 on the hosts' public IPs, mesh sweep, one full-range shard |
| `manager-security-tls` | daily 02:30 | testssl on public and internal endpoints; harvests SANs |
| `manager-security-web` | weekly Sat 02:50 | nuclei (needs the SANs from 02:30) |

**Why a 5-minute sensor exists alongside the daily bundle.** The most likely and most serious finding
— someone publishes `-p 5432:5432` on a host — should not wait until 01:00 the next day. Two sources
cover it in 5 minutes without touching any host: the manager's local `ss`+`docker ps`, and
`read/ListDockerContainers`, which **already returns the bind IP of every published port** (verified:
`gims-postgres: 100.64.0.2:5432->5432/tcp`, `gims-traefik: 51.77.217.160:443->443/tcp`). The Docker
half of exposure drift is an API poll, exactly like `/metrics/containers`. Only the daily bundle sees
**non-Docker** listeners (sshd, tailscaled, a native postgres) and `network_mode: host` containers,
which change rarely.

Flags and guards:

- `nmap -Pn -sT -n --top-ports 200 -T3 --max-rate 100 --max-retries 2 --host-timeout 120s -oG -`
  daily; full range split across 7 nights (`--max-rate 50 -T2 --scan-delay 10ms`, ~3 minutes of
  traffic indistinguishable from background noise, full coverage every 7 days). No external `-sU`:
  it needs raw sockets, is slow and unreliable, and the only UDP that matters (`41641`) is covered by
  the local sensor.
- `nuclei -rate-limit 20 -c 10 -bulk-size 10 -severity low,medium,high,critical
  -exclude-tags intrusive,dos,fuzz,brute-force -disable-update-check -no-interactsh -jsonl`.
  **`-no-interactsh` is not optional**: OAST callbacks are an outbound channel from the control plane
  to a public third party and leak internal hostnames. Excluding `info` is the largest noise
  reduction available. Templates come from a persistent cache refreshed in a **separate** step, so a
  scan never blocks on or is skewed by a fetch.
- **nuclei is never pointed at `https://${PUBLIC_DOMAIN}/provisioning/...`**: those URLs are
  capabilities (the uuid *is* the secret) and `POST /provisioning/<uuid>/burn` destroys an onboarding
  link. Targets are scheme+host roots only, and `-exclude-tags fuzz` keeps path-fuzzing templates
  away.
- **Alertmanager silence around the nuclei window only**, matcher `app="segcore"`, marker
  `createdBy=secaudit` (distinct from the deploy silence), TTL = scan budget + 10 min so it
  self-expires if the scan hangs. From the host there is no route to `alertmanager:9093`, so it goes
  through `docker run --rm --network manager-komodo curlimages/curl`, the idiom already in
  `backup-manager.sh`.
- **Backup-window interlock.** `backup-manager.sh` **stops** step-ca, grafana and
  komodo-core/ferretdb/postgres at 04:00 UTC; a scan overlapping that produces false "invalid cert" /
  "port closed" findings and fails discovery. Two guards, both needed: schedules confined to
  01:00-03:30 UTC, and `sec_require_no_backup()`
  (`systemctl is-active --quiet manager-backup.service` → skip with a metric). Do **not** use
  `Conflicts=manager-backup.service` — that would *stop the backup*. Plus
  `sec_require_free_disk`: below the threshold a scan skips with a metric instead of filling the
  disk.
- **Discovery cache with a shrink guard.** Komodo unreachable → keep `targets.json` and emit
  `secaudit_discovery_ok 0`. Komodo answers with fewer targets than before (a Server deleted, a key
  demoted) → **keep the cache** and emit `secaudit_discovery_shrunk 1`: reducing coverage must be an
  explicit human decision, never an accident. `PUBLIC_BIND_IP=CHANGE_ME` or an unresolved `[[...]]`
  → no public target and `secaudit_target_incomplete{host}`, so a half-onboarded host is not
  mistaken for a clean one.
- **Courier freshness and exit code** come from `read/InspectDeploymentContainer` (not
  `GetDeploymentContainer`, which the schema documents as a cached copy on Core). `execute/Deploy`
  returns when the container starts, not when it finishes, so the pattern is: `Deploy` → poll every
  5s until `State.Running == false` or timeout → on timeout `execute/StopDeployment` and record
  `exit_code = -1`.
- **Host offline** (`info.state != "Ok"`): emit `secaudit_host_scannable 0` and **do not zero or
  delete previous findings**. Zeroing on failure would make a network blip look like "all
  vulnerabilities fixed" — the same class of bug as a stale trivy DB.
- `send_alerts: false`, `poll_for_updates: false`, `auto_update: false` on the couriers.
  `send_alerts` stops a container that exits on purpose every day from generating
  `ContainerStateChange` e-mails; `auto_update` matters more than usual because this Komodo already
  has a `Global Auto Update` Procedure that would redeploy them out of band, destroying an
  unharvested log. Tag `secaudit`, **never `segcore`** (a tag-based `BatchPullRepo`/`BatchDeploy`
  would sweep them up).

## Phases

Each phase is independently useful, which matters because this is the largest single addition to the
repo.

1. **[DONE] `security-lib.sh` + `discover` + `fast` + exporter + rules + dashboard.** On its own,
   and without touching any host, it catches a stray `-p 5432:5432` within 5 minutes (via
   `ListDockerContainers`) and turns the 60022/no-firewall reality into a metric. Best value/effort
   by a wide margin. Built:
   - `scripts/security-lib.sh`, `security-discover.sh`, `security-fast.sh`, `secaudit.sh`
   - `security_metrics_text()` + `GET /metrics/security` in `provisioning/server.py`
   - `security/baseline/ports.toml`, `security/suppressions.toml`
   - `docker/vmalert/rules/security/security-alerts.yml` (4 groups, 14 rules), the
     `scope="secaudit"` Alertmanager child route, the `security` scrape job, the Grafana
     `security` folder and the Homepage group
   - `scripts/systemd/manager-security-fast.{service,timer}`

   Deferred deliberately: the `secaudit-*` filter in `container_metrics_text()` waits for phase 2,
   because it is dead code until the courier containers exist. The `mesh` bind perspective is
   reported (`secaudit_listener` with `scope="mesh"`) but not evaluated against the baseline: the
   Docker-API view only sees published ports, so a mesh verdict needs the native bundle's socket
   table first.
2. **[DONE] Native bundle + courier + `security-collect`.** The bundle, the installer and the
   host units are built and validated on the manager (2026-09-06). The courier Deployments and
   `security-collect.sh` are not written yet, and no host has the bundle installed. What testing on
   the manager — deliberately the worst-case machine — changed:

   - **A killed run used to lose everything.** The report was only written at the end, so a
     `TimeoutStartSec` kill at 28 minutes discarded the work AND left the manager serving the
     previous run's data with no signal. `run.py` now checkpoints after every step and flushes on
     SIGTERM with `partial: true` in the `end` record. Verified by killing a run at 60s: 622
     records survived, correctly marked partial.
   - **`--skip-java-db-update` aborted the scan of any image containing JARs.** The plan assumed no
     image in the fleet had Java; `ankane/pghero` does, and trivy fails hard rather than degrading.
     Java archives are now excluded from analysis by default and the resulting gap is published
     (`SECAUDIT_TRIVY_JAVA`, and a `trivy_policy` record) instead of being silent.
   - **The trivy step had no budget of its own** and let the unit SIGTERM it mid-image. It now stops
     cleanly at `TIMEOUTS["trivy"]` and reports how many images it did not reach.
   - **Alphabetical order plus a step budget meant the tail of the list would never be scanned,
     permanently and silently.** A persisted cursor now rotates the starting point between runs, so
     every image is reached within a few days, and unscanned images are emitted as `image_skipped`.
   - **Capacity, measured not guessed:** the manager (2 vCPU, 29 images, 10 GB) gets through about
     14 images in a 30-minute budget; large language-heavy images like `grafana/grafana` take 200s+
     on their own. This is a property of the box, not a bug — the app hosts have 4-8 cores and
     23-31 GB and will not hit it. Rotation is what makes partial coverage acceptable.
   - **Containment verified under real load:** during a full scan the cgroup pinned at 767-770 MB
     against `MemoryHigh=768M`, host free memory *rose* rather than collapsing, and all 16
     containers stayed up. The same workload run OUTSIDE the unit the day before OOM-killed
     VictoriaMetrics and took the host down. Run it through systemd, never `./run.py`.

   **Rollout as it actually stands (2026-09-06):** the bundle is installed on the manager (timer
   disabled — it is the tight machine and a full trivy pass takes ~33 min there) and on
   `segcore-demo`, which is the only machine with the timer enabled. `segcore-host1` is
   deliberately left for later: it carries the real tenants, and a soak on the machine without
   them costs nothing. Consequence for the collector, which is not written yet: a host with no
   bundle must be a distinct, NON-alerting state — not staleness. Treating "never enrolled" as
   "stale" would page about a decision that was made on purpose.

   First real run on `segcore-demo` (292s, 454 records, zero errors) produced these findings, which
   are what the tool exists for and are tracked outside this document:
   - Komodo Periphery `:8120` is reachable from the internet on BOTH app hosts. The bind is
     deliberately wildcard (`onboard-host.sh:194` — binding it to the mesh IP would recreate the
     boot-ordering deadlock that took Traefik down on the manager), and the design names three
     layers: `allowed_ips`, the Core key, and the host firewall. The first two hold — verified, it
     rejects with `requesting ip ... not allowed` before any auth. The third is simply absent.
   - SSH posture is inconsistent: `demo` exposes 22 (key-only), `host1` exposes 60022 and accepts
     PASSWORDS, and the manager exposes 60022 key-only. The weakest is the host with real tenants.
   - `traefik:v3.6.13` on demo vs `v3.7.7` on the manager: the internet-facing component is behind.
   - 11 fixable CRITICAL and 291 fixable HIGH CVEs across 12 images.
   - Baselines for the ratchet: lynis hardening index 65 (manager 68), docker-bench 33 failures of
     117 checks.

   Completed 2026-09-06: `scripts/setup-secaudit.sh` (two couriers per server, with the
   name-collision assertion and the `network: "none"` echo-check), `scripts/security-collect.sh`,
   the host-report metric families in the exporter, `security/baseline/bench.toml`, 11 new alert
   rules in three groups, four dashboard panels, and the `secaudit-*` filter in
   `container_metrics_text()` — which only became necessary once the couriers existed.

   Two things the first fleet collection changed:
   - **`in_use` on image findings.** `mongo:8.0` still sits on the manager from before the move to
     FerretDB, with 272 fixable CVEs and no container behind it. Alerting on it would be alerting
     on surface that does not exist, forever. Images are now labelled by whether they back a
     running container, the alerts filter on it, and the budget scans running images first. A
     report written before the field existed is treated as in-use, because assuming otherwise
     would silently switch the alerts off during a rollout.
   - **`*` is a wildcard bind.** `ss` prints `*:8120` for a dual-stack socket, which the scope
     classifier read as "public" — the right verdict for the wrong reason.

   Still open: `install-secaudit.sh` on the manager
   first, then `segcore-demo` (the host without real tenants — that is where you find out what goes
   wrong), then `segcore-host1`. The bundle brings lynis + docker-bench + trivy + listeners at once,
   because they share one `run.sh`, one timer and one collection channel: splitting them would not
   reduce risk, only duplicate work. Includes the onboarding step.
3. **[TODO] `ports` (daily top-200 + shards) + cross-scan in the designated host's `run.sh`.**

   **Design flaw found 2026-09-07, before any of this was built.** The plan says the manager runs
   nmap against each app host's public IP to measure its perimeter. That measurement can be blind:
   the manager is the single source most likely to be in the external firewall's allowlist, because
   it is the machine an operator naturally permits when thinking about Komodo. A port that is
   closed to the whole internet but open to the manager would be reported as OPEN, and — worse —
   a port genuinely open to the world would look the same, so the result cannot be interpreted.
   We hit this for real while verifying a firewall change to periphery's `:8120`: from the manager
   the port answered on a brand-new connection, and there was no way to tell whether it was
   reachable from anywhere else.
   This is the exact reasoning that put the manager's own cross-scan on an app host, not applied in
   the reverse direction. The `public` perspective for an app host needs a source that is not the
   manager: each app host scanning the OTHER app hosts' public IPs (which also tests the
   host-to-host firewall posture, worth knowing on its own), or an outside vantage point. Whatever
   is chosen, the source must be recorded in the metric — `secaudit_perimeter_port_open` already
   carries `source_host`, and a result is meaningless without it. Starts
   verifying the external firewall's allowlist and the Headscale ACL.
4. **[TODO] `tls`.** Brings `InternalTlsNotRenewing`, the second most valuable alert in the set.
5. **[TODO] `web` (nuclei)** — the only one that touches the apps, hence last.

## Risks and recorded decisions

1. **There is now software installed on the hosts, with a real maintenance cost.** Three pinned
   artifacts per machine that somebody has to update. Mitigation: versions and hashes live in one
   git file (`bootstrap/secaudit/versions.env`), the installer is idempotent, and
   `secaudit_tool_version_info{host,tool,version}` makes version divergence visible on the dashboard
   instead of invisible. `run.sh` runs as root — the most review-sensitive file in the set, which is
   why it reads nothing from outside `/opt/secaudit` and takes no network parameters.
2. **Updates depend on SSH break-glass**, because there is no root exec path through the Komodo API.
   It is the mechanism `onboard-host.sh` already designates for OS operations, but it is manual and
   not audited by Komodo. Acceptable for something that happens a few times a year; the alternative
   (`/terminal/execute`) is worse on every count.
3. `DeploymentConfig.network` **defaults to `host`** in the Komodo schema. Asserted in the
   installer's echo-check (`read/GetDeployment` + `read/ExportResourcesToToml` parsing) — the class
   of bug that has already bitten this repo three times.
4. docker-bench's JSON can come out invalid; without the text-log fallback one malformed check zeroes
   the whole benchmark and the dashboard goes green.
5. **Lynis will produce many warnings on its first run** — normal, a default Ubuntu has dozens of
   suggestions. Without the per-section budget mechanism the first e-mail is useless. Bootstrap flow:
   run, accept the observed counts as the initial budget in the commit, and from then on alert only on
   **regression**. `lynis_hardening_index` stays a trend metric, never an alert.
6. Each courier `Deploy` creates a Komodo Update record. At daily cadence plus retry that is
   ~1 500/year for two hosts — irrelevant. **This is why collection is daily and not every 30
   minutes**: collecting more often than the bundle produces adds no information and multiplies
   records in FerretDB, which lands in the daily encrypted backup. Confirm Core's update retention
   and record it in `INSTRUCTIONS.md`.
7. `DESIGN.md` is stale about the firewall and the sshd bind. Fix the doc as part of this work so
   the baseline and the documentation do not contradict each other.
