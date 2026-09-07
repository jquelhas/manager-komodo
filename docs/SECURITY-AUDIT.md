# Security audit — runbook

What runs, how to read it, what to do when it alerts. The design and the reasoning are in
[plan/secaudit.md](plan/secaudit.md); this file is the operational half.

**Phases 1 and 2 exist today.** The fast exposure sensor and the internal-name drift check
(phase 1), plus the native host bundle — lynis, docker-bench-security, trivy, the socket table and
the perimeter cross-scan — collected from each host through a zero-privilege courier (phase 2). The
external nmap/testssl/nuclei scans run FROM the manager are phases 3-5 and are not built yet;
`secaudit.sh run <that scan>` says so rather than silently doing nothing.

## Install

The units are versioned in `scripts/systemd/` but, as with `manager-backup`, the repo does not
install them for you:

```bash
sudo cp scripts/systemd/manager-security-fast.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now manager-security-fast.timer
systemctl list-timers manager-security-fast.timer
```

Everything else is already wired: `provisioning` mounts `./security` read-only and serves
`/metrics/security`, VictoriaMetrics scrapes the `security` job every 60s, vmalert loads
`docker/vmalert/rules/security/*.yml`, and the Grafana dashboard is provisioned into the
**security** folder (`https://grafana.apps.internal/d/security-overview`).

Without the timer, nothing is broken — it just means the scans only run when you run them, and
`SecurityScanStale` will eventually fire and tell you so.

## Enrolling a host (phase 2)

The manager has no SSH to the app hosts, and nothing on them listens for it. Installation is
carried by an operator; collection then goes over the Komodo link that already exists.

```bash
# on the manager: package the bundle and publish it as a one-time link
scripts/secaudit.sh bundle --serve

# on the host, as an operator with sudo — the URL is printed above
sudo bash -c "$(curl -fsSL <url>)" -- --dry-run
sudo bash -c "$(curl -fsSL <url>)" -- --no-enable
sudo systemctl start secaudit-host.service     # ONE run, watched. 5-10 min
/opt/secaudit/run.py --summary                 # read-only digest, no sudo
sudo systemctl enable --now secaudit-host.timer secaudit-host.path
```

Exactly one host also runs the perimeter cross-scan, which is the only measurement of the external
firewall allowlist and of the app-host → manager ACL deny:

```bash
sudo apt-get install -y nmap
sudo bash -c "$(curl -fsSL <url>)" -- --perimeter-targets "manager_public=<PUBLIC_IP> manager_mesh=100.64.0.1"
```

Re-running the installer is idempotent and keeps the perimeter targets if you do not repeat them.
Then, on the manager, create the couriers once and collect:

```bash
scripts/setup-secaudit.sh          # two Deployments per Komodo server; asserts no name collision
scripts/secaudit.sh run collect
sudo cp scripts/systemd/manager-security-collect.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now manager-security-collect.timer
```

**A host without the bundle is a deliberate state, not a fault.** `secaudit_host_enrolled` goes to
0 and nothing else is emitted for it — no staleness, no alert. The fleet is enrolled one machine at
a time on purpose, and paging about that decision is how an alert stream gets ignored.

## Day-to-day

```bash
scripts/secaudit.sh status              # what ran, how old, and whether it is stale
scripts/secaudit.sh run all             # run everything implemented, now
scripts/secaudit.sh run fast --dry-run  # print what would run, execute nothing
scripts/secaudit.sh show ports          # exposed ports and the baseline verdicts
scripts/secaudit.sh show listeners      # the manager's socket table
scripts/secaudit.sh show drift          # internal-name checklist
scripts/secaudit.sh show suppressions   # accepted risks and their expiry
scripts/secaudit.sh metrics             # the exact exposition VM scrapes
```

## The one thing to understand before trusting a green dashboard

There are three perspectives and they measure **different things**:

| Perspective | Measures | Built in |
|---|---|---|
| `local` | what is **bound** to a routable address | phase 1 |
| `public` | what the **external firewall** lets through | phase 3 |
| `mesh` | what the **Headscale ACL** permits | phase 3 |

This fleet has **no host firewall** — the external OVH firewall is the authoritative gate and is
invisible from inside the machine. So `local` is a *drift* signal: it catches a stray
`-p 5432:5432` within 5 minutes, but a port being bound does not by itself mean it is reachable.
Only the `public` perspective measures the real perimeter, and it does not exist yet.

And: **a stale scan is not a clean scan.** Read the *Frescura dos scans* table first.

## Changing policy

Both files are in git, and both are evaluated **at scrape time** — an edit takes effect within
~60 seconds, with no re-scan.

- `security/baseline/ports.toml` — what is expected. Adding an entry here is **permanent
  acceptance**. Composition is `defaults.<role>.<perspective>` plus per-host `extra_*` minus
  per-host `remove_*`.
- `security/suppressions.toml` — what is accepted **temporarily**. `expires` is mandatory, capped
  at `SECAUDIT_MAX_SUPPRESSION_DAYS` (180). A suppression does not hide a finding: it relabels it
  `suppressed="1"`, so it stays exported and on the dashboard, and only the alert rules skip it.
  An entry that is malformed, expired or beyond the horizon **suppresses nothing** and raises
  `SecuritySuppressionInvalid` — deliberately, because an operator who believes a finding is
  silenced when it is not is the worst outcome.

Rule of thumb: permanent facts about the architecture go in the baseline; anything you intend to
fix goes in a suppression with a date and an owner.

## Alerts and first actions

| Alert | What it means | First action |
|---|---|---|
| `UnexpectedExposedBind` | Something is bound to `0.0.0.0` or the public IP and is not in the baseline | `scripts/secaudit.sh show ports`. Decide: unpublish it, add it to the baseline, or add a dated suppression |
| `ExpectedPortClosed` | A `required_tcp` port is not there | The service is down, or it stopped being published. Check the host |
| `InternalNameMisconfigured` | `missing=dns` → add to `dns.extra_records` in `docker/headscale/config.yaml` and `docker compose restart headscale`. `missing=stepca_hosts` → add to the step-ca `extra_hosts` block in `docker-compose.yml`. `missing=router` → **a step-ca entry with no router**: it can never answer TLS-ALPN-01 and it stalls the whole internal renewal queue. Remove it | Fix the named file. This is the 2026-08-23 failure mode |
| `SecurityScanStale` / `SecurityScanFailing` | The sensor was never scheduled, stopped, or errors out | `scripts/secaudit.sh status` — it now says so explicitly when the timer is not enabled, which is the usual cause right after setting this up. Otherwise `systemctl status manager-security-fast.service`, then `scripts/secaudit.sh run all` and read the output |
| `SecurityScanTargetsEmpty` | A scan succeeds but audits nothing | Check `security/state/targets.json` and `discovery.json` |
| `SecurityDiscoveryDegraded` | Komodo unreachable, or it returned far fewer targets and the cache was kept | `security/state/discovery.json` carries the reason. Shrinking coverage must be deliberate: delete `targets.json` to accept a smaller fleet |
| `SecurityExporterDown` | VM cannot scrape the exporter | `docker compose logs provisioning`. Every security alert is blind meanwhile |
| `SecurityStateUnreadable` | The exporter cannot parse a state or policy file | Named in `{{ $labels.file }}`. Missing data must never read as "no findings" |
| `SecuritySuppressionInvalid` | A suppression suppresses nothing | Fix or delete the entry in `security/suppressions.toml` |
| `SecurityHostReportStale` | A host stopped reporting for 36h | On the host: `systemctl status secaudit-host.timer`, then `systemctl start secaudit-host.service` |
| `SecurityHostReportPartial` | The last run was killed before finishing | Usually `TimeoutStartSec` on a slow machine. `/opt/secaudit/run.py --summary` on the host says which step was reached |
| `SecurityHostScannerFailing` | One scanner has failed for a day | A coverage gap in that tool only; the others still ran |
| `TrivyDbStale` | The vulnerability DB is over 48h old | Silent false negatives: the dashboard goes green while new CVEs go unseen. Check the host's egress to ghcr.io |
| `ImageCriticalVulnFixable` | Fixable CRITICAL CVEs in a **running** image | Rebuild or repull. Images that back no container are excluded on purpose — alerting on them is alerting on surface that does not exist |
| `PendingVulnerablePackages` | Lynis found vulnerable OS packages | The auditor never runs apt; updating is your call |
| `LynisFindingsRegression` / `DockerBenchRegression` | Hardening findings above the committed budget | Either something regressed, or `security/baseline/bench.toml` needs a **reviewed** increase — never a silent one |
| `PerimeterUnexpectedPort` | A port is reachable that the baseline does not allow | `_mesh` target → Headscale ACL regression, fix `acl.hujson`. `_public` target → the external firewall is letting something through |
| `PerimeterScanStale` | The cross-scan has not run in 48h | The firewall allowlist and the ACL deny are unverified meanwhile |
| `SecurityFindingsTruncated` | A metric family hit the per-family series cap | Almost always a degenerate scan. Investigate before raising `_SEC_MAX_SERIES` |

Security alerts are routed by the `scope="secaudit"` child route in
`docker/alertmanager/alertmanager.yml.tmpl` with `repeat_interval: 24h` — a daily digest, not a
pager. None of them carries `app="segcore"`, so the 30-minute deploy silence cannot blind them.

## Self-test

Prove the sensor works end to end, in about a minute:

```bash
# loopback: reported, but NOT a finding
docker run -d --rm --name secaudit-selftest -p 127.0.0.1:19999:80 traefik/whoami:latest
scripts/secaudit.sh run all && scripts/secaudit.sh show ports | grep 19999   # expect nothing
docker rm -f secaudit-selftest

# wildcard: MUST become a finding
docker run -d --rm --name secaudit-selftest -p 0.0.0.0:19998:80 traefik/whoami:latest
scripts/secaudit.sh run all && scripts/secaudit.sh show ports | grep 19998   # expect unexpected=1
docker rm -f secaudit-selftest
scripts/secaudit.sh run all     # finding disappears -> the alert resolves
```

The last step matters: findings are emitted *only while they exist*, so alerts resolve on their
own. Counts stay at 0, so a dashboard never reads `No data` and "clean" is never confused with
"exporter broken".

**Resolution is not instant, and that is normal.** An instant query returns the last sample within
VictoriaMetrics' lookbehind window (5 minutes by default), so after a finding stops being exported
the expression keeps returning it until that window passes — and the rule group only re-evaluates
every 5 minutes. Expect up to ~10 minutes between fixing a finding and the alert clearing. If it
has not cleared after that, check the series itself is gone:

```bash
scripts/secaudit.sh metrics | grep secaudit_port_unexpected   # from the exporter
# and from VM (empty result = gone):
docker exec manager-pghero-postgres wget -qO- \
  'http://victoriametrics:8428/api/v1/query?query=secaudit_port_unexpected'
```

## Changing the metrics or the exporter

The exporter is `security_metrics_text()` in `provisioning/server.py`. It is bind-mounted as a
single file, so applying a change needs a recreate, not a restart:

```bash
docker compose up -d --force-recreate provisioning
```

Adding a rule *file* under `docker/vmalert/rules/security/` hot-reloads in 30s. Adding a new rule
*directory* needs a new `-rule=` flag in `docker-compose.yml` and `docker compose up -d vmalert`,
because `-rule` is a start-up flag.
