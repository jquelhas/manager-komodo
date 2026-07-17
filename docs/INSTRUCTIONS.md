# Host provisioning (onboarding an app host)

How to bring a new application host under the `manager-komodo` control plane. One command on the
manager, one command on the host. Additive and non-disruptive — it does **not** touch the running
application.

## What onboarding does

1. Installs (natively) the **Tailscale** client and **Docker** (if missing), and joins the host to
   the Headscale mesh with the app tag `tag:<role>` (default `tag:segcore`).
2. Installs **Komodo Periphery** as a systemd service (root) — `periphery.service`, listening on
   `:8120`, accepting only our Core's key, from the mesh range.
3. **Auto-registers** the host in Komodo Core: creates the **Server** (`https://<mesh-ip>:8120`) and,
   for the app role, the deploy **Repo** (`segcore-<host>`, tagged `segcore`).
4. Metrics are then **auto-discovered** by VictoriaMetrics (from the Komodo server list) and the app
   shows up in Grafana; deploys are triggered from Komodo.

Rollback safety: if the host already runs another overlay (e.g. Netbird) and joining the mesh breaks
it, the installer runs `tailscale down` and aborts. A read-only preflight aborts before any change
on incompatible hosts.

## Prerequisites

- Host: Ubuntu/Debian, root/sudo, egress to `https://komodo.segcore.eu`.
- The app tag must exist in the ACL. `tag:segcore` already does. **For a new app** (`otherapp`),
  first edit [`docker/headscale/acl.hujson`](../docker/headscale/acl.hujson): add
  `"tag:otherapp": ["jferreira@"]` to `tagOwners` **and** a rule
  `{ "action": "accept", "src": ["tag:manager"], "dst": ["tag:otherapp:3000,9187,8120"] }`, then
  `docker compose restart headscale`.

## 1. Generate the onboarding link (on the manager)

```bash
cd /opt/manager-komodo
./add-host.sh                 # defaults: --role segcore --ttl 5m
# other apps:  ./add-host.sh --role otherapp
# more time:   ./add-host.sh --ttl 30m
```

It prints a one-time command. The link is one-time (burns when onboarding completes) and expires
after the TTL. It carries a one-shot, tag-scoped Headscale pre-auth key.

## 2. Run it on the NEW host (as root)

Dry-run first (checks only, changes nothing — confirms no Netbird route conflict, OS, arch, egress):

```bash
sudo bash -c "$(curl -fsSL https://komodo.segcore.eu/provisioning/<uuid>/install.sh)" _ --check
```

If it says **Preflight PASSED**, run for real:

```bash
sudo bash -c "$(curl -fsSL https://komodo.segcore.eu/provisioning/<uuid>/install.sh)"
```

- It prompts for the **hostname** (default = the host's own `$(hostname)`).
  **Tip:** use a plain name like `prod-2` (the Repo becomes `segcore-prod-2`). Do **not** prefix it
  with `segcore-` (that would double it).
- On finish it auto-registers the Server + Repo and burns the link.

## 3. Host-side steps for deploys & metrics

**Before the first Komodo deploy** — allow root's git on the app repo (else `git pull` aborts with
"dubious ownership" mid-deploy and stops the app):

```bash
sudo git config --system --add safe.directory /opt/SEGCORE
```

**Metrics** — the app must bind `backend`/`postgres-exporter` on the mesh IP. In the app `.env`,
`LOCAL_BIND_IP` = the host's mesh IP (`tailscale ip -4`), then
`docker compose up -d backend postgres-exporter`. (Prod hosts already on the mesh usually have this.)

## 4. Verify (from the manager)

```bash
# node on the mesh with the app tag
docker exec manager-headscale headscale nodes list | grep <host>

# Komodo Server healthy (Core reaches the periphery)  — via the API or the UI (https://komodo.apps.internal)
# metrics being scraped
docker run --rm --network manager-komodo curlimages/curl:latest -s \
  'http://victoriametrics:8428/api/v1/query?query=up%7Bhost%3D%22<host>%22%7D'
```
Expected: node present (`tag:segcore`), Server state `Ok`, `up=1` for backend/postgres targets.

## 5. Deploy

- **One host** — Komodo UI: *Repos → `segcore-<host>` → Pull*. Runs `./scripts/update.sh` on the host
  (backup → git pull → build → up). Note: no live log streaming — the full log appears in the Update
  record when it finishes; watch live on the host with `docker compose ps` if needed.
- **All / several** — `BatchPullRepo` by name pattern `segcore-*` or by the `segcore` tag.
  ⚠️ Batch **executes** (it is not a dry-run).
- **Orchestrated / canary** — a Komodo Procedure (sequential/parallel stages), schedulable / webhook.

## Notes & gotchas

- The Periphery serves TLS (self-signed) — the Server address is `https://<mesh-ip>:8120` (Komodo uses
  `wss`, accepts the self-signed cert; security is the Noise key handshake). `http://` fails.
- Netbird coexists with Tailscale; only a real CGNAT route overlap with `100.64.0.0/16` blocks the
  preflight.
- The installer requires `bash` (the one-liner uses `bash -c`).
- Deploy git auth is a **read-only** fine-grained GitHub token (Komodo git account `github.com`/
  `jquelhas`); Komodo can pull, never push.

## Alerting

Two alert sources, **one inbox**. Alertmanager is the notification hub (SMTP e-mail); both sources
feed it, so all alerts arrive by e-mail with dedup/grouping.

- **App metrics → vmalert → Alertmanager.** Rules in [`docker/vmalert/rules/apps/`](../docker/vmalert/rules/apps/)
  (SEGCORE: backend down, 5xx rate >5%/>20%, p95 latency) and
  [`docker/vmalert/rules/platform/`](../docker/vmalert/rules/platform/) (control-plane self-monitoring).
  vmalert fires them via `-notifier.url=http://alertmanager:9093`.
- **Infra → Komodo → Alertmanager.** Komodo Core generates infra alerts (server unreachable,
  CPU/mem/disk thresholds, container/stack state changes). A Komodo **Custom Alerter** POSTs them to
  the internal relay `http://provisioning:8000/alert/komodo` ([server.py](../provisioning/server.py)),
  which maps them to Alertmanager's v2 API. Per-host thresholds live in each Server's config (Komodo UI).

### One-time setup

1. **SMTP config — all in `.env`** (`SMTP_SMARTHOST`, `SMTP_FROM`, `SMTP_AUTH_USERNAME`,
   `SMTP_AUTH_PASSWORD`, `SMTP_REQUIRE_TLS`, `ALERT_EMAIL_TO`; see [.env.example](../.env.example)).
   Nothing SMTP lives in git — the `alertmanager-init` service renders
   [`alertmanager.yml.tmpl`](../docker/alertmanager/alertmanager.yml.tmpl) from these vars into a
   volume at startup. After changing any of them:
   `docker compose up -d alertmanager-init && docker compose restart alertmanager`.
2. **Bring it up:** `docker compose up -d alertmanager && docker compose up -d vmalert provisioning`.
   Verify Alertmanager: `docker exec manager-alertmanager wget -qO- http://localhost:9093/-/healthy`.
3. **Create the Komodo Custom Alerter (once)** — UI *Alerters → New → Custom*, URL
   `http://provisioning:8000/alert/komodo`; or via API:
   ```bash
   curl -s https://komodo.apps.internal/write/CreateAlerter \
     -H "X-Api-Key: $KOMODO_API_KEY" -H "X-Api-Secret: $KOMODO_API_SECRET" -H 'Content-Type: application/json' \
     -d '{"name":"email-hub","config":{"enabled":true,"endpoint":{"type":"Custom","params":{"url":"http://provisioning:8000/alert/komodo"}}}}'
   ```

### Test

- App: stop the backend on a host (`docker compose stop backend`) → `SegcoreBackendDown` fires after
  2m and e-mails; start it → resolved e-mail.
- Infra: disable a Server in Komodo or trip a low CPU threshold temporarily.
- Check the pipeline: vmalert `/api/v1/alerts`, Alertmanager `/api/v2/alerts`.

## Offboard (remove a host)

Delete the Komodo Server + Repo (removes it from monitoring auto-discovery and deploys), then remove
the mesh node:

```bash
docker exec manager-headscale headscale nodes delete -i <node-id> --force
# + delete the Komodo Server and Repo via the UI or API (write/DeleteServer, write/DeleteRepo)
```
