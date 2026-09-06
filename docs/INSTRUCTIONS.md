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

**Deploys run as `ubuntu`** — onboarding sets Periphery to run as the `ubuntu` user (in the `docker`
group) via a systemd drop-in, so Komodo's `git pull` + `on_pull` (update.sh) produce `ubuntu`-owned
files. No `git config safe.directory` hack is needed, and manual `sudo -u ubuntu ./scripts/update.sh`
runs don't collide. (If a host predates this, migrate it: `usermod -aG docker ubuntu`,
`chown -R ubuntu:ubuntu /etc/komodo /opt/SEGCORE`, add the `User=ubuntu` drop-in, restart periphery.)

**Secrets** — nothing to do on the host. They are fleet-wide Komodo Variables, and the host's own
`JWT_SECRET` is generated into `<HOST>_JWT_SECRET` at registration. The only value left to fill in is
`PUBLIC_BIND_IP` (the host's public IP), in the Komodo UI on that Repo's `environment` — the deploy
aborts while it is still `CHANGE_ME`. See §App `.env` management. The `[secrets]` block in
`/etc/komodo/periphery.config.toml` stays commented out; it exists for a value that must never leave
the host, which is not how this fleet is set up today.

**Metrics** — `backend`/`postgres-exporter` must bind the mesh IP. `LOCAL_BIND_IP` is filled in
automatically from the host's mesh IP when the Repo environment is seeded, so no manual edit is
needed; after the first deploy check `up{host="segcore-<host>"}` in §4.

## App `.env` management

The app `.env` on each host is **written by Komodo**, not maintained by hand. Each Repo's
`environment` holds the file's contents; Komodo writes it to `/opt/SEGCORE/.env` (mode `0600`) on
every Clone/Pull, immediately before running `on_pull`. **Editing `/opt/SEGCORE/.env` on the host is
pointless — the next deploy overwrites it.** Change values here instead:

**Secrets are fleet-wide by design** (decided 2026-08-20): one Variable per value, shared by the whole
`segcore` fleet, so there is a single place to manage each one. The mesh ACL denies app-host↔app-host
and app-host→manager traffic, so a credential taken from one host buys no access to another host's
Postgres. A host that needs its own value is the exception, handled in its Repo `environment`.

| kind of value | where it lives | how it is referenced |
|---|---|---|
| fleet-wide (the default, secret or not) | Komodo Variable (*Settings → Variables*), from `APPVAR_*`/`APPSECRET_*` | `[[NAME]]` |
| per host, not sensitive (`LOCAL_BASE_DOMAIN`, `PUBLIC_BIND_IP`) | literal in that Repo's `environment`, edited in the Komodo UI | written directly |
| per host, exception to a fleet-wide secret | literal in that Repo's `environment`, or a host-specific Variable | `[[HOST1_JWT_SECRET]]` |

### The two keys

`JWT_SECRET` is **per host**, generated once at onboarding into the Variable `<HOST>_JWT_SECRET` by
`provisioning/server.py`, and never regenerated — the app `.env` is rewritten on every deploy, so a
value generated at boot-time-if-missing would change on every deploy and log everyone out. Per host
because the app backends are public: a shared signing key would let a token minted on one host
authenticate as admin on every other tenant. Rotating it only ends sessions (the longest token is the
30-day "remember me"); it destroys no data, **provided `TENANT_CONFIG_KEY` is set**.

`TENANT_CONFIG_KEY` encrypts data at rest — tenant config, integration credentials, SMTP credentials.
It is fleet-wide on purpose, because it has to travel with the data for a backup from one host to be
restorable on another. The app resolves
`TENANT_CONFIG_KEY || JWT_SECRET || 'default-key-change-me'`, so two rules follow: its value must be
the key the existing ciphertext was encrypted with (on a host that never had it set, that is that
host's **current** `JWT_SECRET`), and it must never go back to empty, or at-rest encryption silently
falls back to a `JWT_SECRET` that may since have been rotated. `update.sh` on the host fails the deploy
on an empty value.

`BACKUP_ENCRYPTION_KEY` is fleet-wide by decision: restoring one host's backup on another (failover
drills, debugging) is a wanted capability and needs one key. `DB_PASSWORD` is not free to choose at
all — it must match what that host's Postgres cluster was initialised with.

Note that `read/GetRepo` returns a literal in clear to anyone with read access on the Repo, which is
why a host-specific Variable is preferable to a literal for an exception that is sensitive. And an
override can **not** be done by putting the same name in the host's periphery `[secrets]`: Core
interpolates first, so the periphery never sees it. Komodo Variables are also **not encrypted at
rest** — the Core config file's `[secrets]` block is the hardening option for shared secrets.

**Careful:** an unknown `[[NAME]]` is *not* an error — Komodo writes it through literally. Therefore
`scripts/update.sh` in the app repo aborts the deploy if any `[[` survives in the written `.env`.

**Komodo does not copy the environment verbatim**: it parses it into `KEY=value` pairs and
re-serialises them, so comments and blank lines are stripped from the file the host receives. Values
survive verbatim — `#`, `=`, `&`, `$`, `%`, `{}`, quotes and inner spaces were all verified on 2.2.0.
Two exceptions: **trailing whitespace is trimmed**, and **whitespace followed by `#` is treated as an
inline comment** and truncates the value. Both apply to interpolated values too, because Core
substitutes before the file is parsed — so avoid `" #"` in generated passwords.

**Quoting has three consumers with three different rules**, so keep shell metacharacters out of
values altogether — generate secrets with `openssl rand -hex 32`, never a passphrase with `&` or
spaces. Komodo writes the value verbatim (quotes are not syntax to it and end up in the file);
`./scripts/update.sh` on the host **sources** the file as shell, so an unquoted `& | ; < > ( ) `` `
or space aborts the deploy — `DEFAULT_ADMIN_PASSWORD=M&Wnode&2000` gave `Wnode: command not found`
on 2026-08-21 — and such a value must be quoted; docker compose strips surrounding quotes on
`${VAR}` interpolation but `env_file:` does not, so a quoted value reaches some containers with the
quotes attached. `scripts/setup-app-env.sh` lints for this on the resolved values before a deploy. Comments in the template/environment are therefore for
whoever edits it in Komodo. When diffing a rendered environment against a host's existing `.env`,
compare assignments only — e.g.
```bash
KEYS='^[A-Za-z_][A-Za-z0-9_]*='   # note the digits: BACKUP_S3_* would be missed by [A-Z_]+
diff <(scripts/setup-app-env.sh --print segcore-demo | grep -E "$KEYS" | sort) \
     <(grep -E "$KEYS" captured.env | sort)
```

```bash
# lint + show what would change, for every segcore-* Repo (no writes)
scripts/setup-app-env.sh
# push the fleet-wide Variables from APPVAR_*/APPSECRET_* in .env, seed empty environments
scripts/setup-app-env.sh --apply
# render one host's .env to stdout (to diff against what is on the host today)
scripts/setup-app-env.sh --print segcore-demo
```

`LOCAL_BIND_IP` is derived from the Server's mesh address, so it is never set by hand. **Everything
else that differs per host is set in the Komodo UI, not in this repo** — that way onboarding a host
never means editing the manager's `.env`. The template ships those values as `CHANGE_ME`; after the
Repo is seeded, open *Repos → `segcore-<host>` → Config → Environment* and fill them in. A legacy
host that needs its own `COMPOSE_PROJECT_NAME` or `NODE_ENV` gets it the same way: edit the line in
its `environment`, or add one.

Forgetting to fill one in is caught, not silently deployed: `scripts/update.sh` in the app repo
aborts on `[[` **and** on `CHANGE_ME`.

The template is `provisioning/app-env.template`; new hosts are seeded from it automatically at
onboarding (`provisioning/server.py`). The script only seeds an **empty** `environment` — once
populated, the Komodo UI is the source of truth and `--force` is required to re-seed from the
template (which would discard the per-host values entered in the UI).

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

**Caminho recomendado — Procedure `deploy-segcore`** (silencia os alertas durante o rebuild, ver
[§Alerting → Silences de manutenção](#silences-de-manutenção-no-deploy)). No Komodo UI: *Procedures
→ `deploy-segcore` → Run*. Faz `silence-on → BatchPullRepo segcore-* → silence-off`, ou seja corre
`./scripts/update.sh` em toda a frota `segcore-*` sem gerar e-mails de *backend down/up*. Instalar/
atualizar uma vez com `scripts/setup-deploy-procedure.sh` (ver §Alerting).

Alternativas manuais (⚠️ **não silenciam** — geram os e-mails de down/up durante o rebuild):
- **One host** — Komodo UI: *Repos → `segcore-<host>` → Pull*. Runs `./scripts/update.sh` on the host
  (backup → git pull → build → up). **Logs:** the full output is in the Update record when it finishes
  (toggle **Poll** on the log tab for near-realtime); for a live view, `update.sh` also tees to
  `/opt/SEGCORE/logs/update-<ts>.log` on the host — `tail -f /opt/SEGCORE/logs/update-*.log`.
- **All / several** — `BatchPullRepo` by name pattern `segcore-*` or by the `segcore` tag.
  ⚠️ Batch **executes** (it is not a dry-run).

## Notes & gotchas

- The Periphery serves TLS (self-signed) — the Server address is `https://<mesh-ip>:8120` (Komodo uses
  `wss`, accepts the self-signed cert; security is the Noise key handshake). `http://` fails.
- Netbird coexists with Tailscale; only a real CGNAT route overlap with `100.64.0.0/16` blocks the
  preflight.
- The installer requires `bash` (the one-liner uses `bash -c`).
- Deploy git auth is a **read-only** fine-grained GitHub token (Komodo git account `github.com`/
  `jquelhas`); Komodo can pull, never push.

## Internal TLS expired (`*.apps.internal`)

Symptom: every internal service stops answering over HTTPS at once, and anything using the step-ca
root as a CA bundle fails — including `scripts/setup-app-env.sh` and `scripts/setup-deploy-procedure.sh`:

```
curl: (60) SSL certificate OpenSSL verify result: certificate has expired (10)
[x] cannot reach the Komodo API at https://komodo.apps.internal
```

Note this does **not** affect anything talking over the Docker network (`http://komodo-core:9120`) or
the public entrypoint (Let's Encrypt, separate resolver) — so the control plane can look healthy while
every internal UI is unreachable.

Diagnose:

```bash
# which certificate is served, and until when
echo | openssl s_client -connect 100.64.0.1:443 -servername komodo.apps.internal 2>/dev/null \
  | openssl x509 -noout -dates
# why the renewal failed
docker logs --since 24h manager-traefik 2>&1 | grep -iE 'acme|renew|error' | tail -20
```

Two causes seen so far, both real:

1. **step-ca was down when Traefik tried to renew.** Certificates live 24h and are renewed with zero
   margin (see `docs/DESIGN.md`, "Margem de renovação"), so a 45-second outage is enough — and
   `scripts/backup-manager.sh` stops step-ca for exactly that long. Traefik only retries 24h later.
   Fix: `docker compose restart traefik`, which forces a renewal pass immediately.

2. **A dead entry in the ACME store blocks the whole queue.** Traefik renews sequentially; a domain
   that can never validate — one no longer routed, or missing from step-ca's `extra_hosts`, so the
   TLS-ALPN challenge cannot resolve it — hangs and nothing after it renews. Look for a `Trying
   renewal` line with a large negative `hoursRemaining` and no result after it. Fix:

   ```bash
   docker compose stop traefik
   sudo cp -a docker/traefik/certs/acme-stepca.json docker/traefik/certs/acme-stepca.json.bak-$(date +%Y%m%dT%H%M%S)
   sudo sh -c 'jq ".stepca.Certificates |= map(select(.domain.main != \"DEAD.apps.internal\"))" \
     docker/traefik/certs/acme-stepca.json > /tmp/a && cat /tmp/a > docker/traefik/certs/acme-stepca.json && rm /tmp/a'
   docker compose start traefik
   ```

   (2026-08-23: `test.apps.internal`, left over from bring-up and expired 38 days, was blocking every
   other renewal.)

Verify: re-run the `openssl s_client` above — `notAfter` should be ~24h ahead — and check the other
hosts too, since one blocked entry stalls all of them.

## Security audit

The control plane audits its own and the fleet's security posture. Runbook:
[SECURITY-AUDIT.md](SECURITY-AUDIT.md); design and decision record:
[plan/secaudit.md](plan/secaudit.md).

Today (phase 1) a 5-minute sensor turns two things into metrics with alerts: any port **bound to a
routable address** across the fleet — a stray `-p 5432:5432` is visible within 5 minutes, with no
agent on the hosts — and drift in the internal-service checklist below, including the
step-ca-entry-without-a-router case that stalls every internal certificate renewal (see *Internal
TLS expired*). Findings land in the same inbox as everything else, on a `scope="secaudit"` route
with a 24h repeat rather than the global 4h.

Two commands worth knowing: `scripts/secaudit.sh status` and `scripts/secaudit.sh run all`.
Policy (what is expected, what is accepted and until when) is in git under `security/` and is
evaluated at scrape time, so an edit takes effect in ~60s without re-running a scan.

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

### Silences de manutenção no deploy

Um deploy reconstrói os containers, por isso o backend fica `up=0` durante o rebuild e a regra
vmalert `SegcoreBackendDown` dispararia (e-mail *backend down* + depois *backend up* ao resolver).
Para não alertar num down **planeado**, o deploy é feito pela Procedure **`deploy-segcore`**, que
envolve o `BatchPullRepo` com duas Actions que abrem e fecham um **silence** no Alertmanager:

- `segcore-silence-on` — cria um silence (matcher `app="segcore"`) com TTL de 30 min. É
  **time-boxed**: auto-expira mesmo que o deploy falhe/pendure, portanto nunca fica um silence preso.
- `segcore-silence-off` — apaga o silence no fim (procura-o pelo marcador `createdBy=komodo` +
  `comment="segcore deploy"`, sem precisar de passar o id entre stages).

As Actions correm no runtime Deno do Komodo Core, que está na mesma rede Docker que o Alertmanager,
logo falam com `http://alertmanager:9093/api/v2/silences` diretamente (sem mesh, sem token). O
código-fonte está em [`docker/komodo/actions/`](../docker/komodo/actions/).

**Instalar / atualizar (idempotente):**
```bash
./scripts/setup-deploy-procedure.sh   # usa KOMODO_API_KEY/SECRET do .env; KOMODO_URL default https://komodo.apps.internal
```
Cria/atualiza as duas Actions e a Procedure `deploy-segcore`. Re-correr após editar os `.ts`.

⚠️ O silêncio só se aplica quando o deploy passa pela Procedure. Um *Repo Pull* direto (ou
`update.sh` à mão no host) **não** silencia. Fora de uma janela de deploy, `SegcoreBackendDown`
continua a alertar normalmente ao fim de 2 min.

## Offboard (remove a host)

Delete the Komodo Server + Repo (removes it from monitoring auto-discovery and deploys), then remove
the mesh node:

```bash
docker exec manager-headscale headscale nodes delete -i <node-id> --force
# + delete the Komodo Server and Repo via the UI or API (write/DeleteServer, write/DeleteRepo)
```
