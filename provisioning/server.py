#!/usr/bin/env python3
"""One-time provisioning endpoint for manager-komodo host onboarding.

Serves per-UUID install scripts written by add-host.sh into STORE_DIR, with one-time /
TTL semantics. It never faces the internet directly — Traefik terminates TLS, rate-limits,
and is the only public listener. Runs as a non-root user; only STORE_DIR is writable.

Routes:
  GET  /provisioning/<uuid>/install.sh  -> serve the script (200) or identical 404
  POST /provisioning/<uuid>/burn        -> delete the entry (204), idempotent

The URL is a capability: the <uuid> IS the secret. So: unknown / expired / burned all
return the SAME 404 (no enumeration oracle), the uuid is validated as strict v4 before any
filesystem access (+ realpath containment), and the uuid is REDACTED from logs (logging the
path would log the secret). Response bodies are never logged.
"""
import datetime
import fnmatch
import http.server
import json
import os
import re
import secrets
import shutil
import socketserver
import threading
import time
import tomllib
import urllib.error
import urllib.request

STORE_DIR = os.path.realpath(os.environ.get("STORE_DIR", "/store"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))
REAPER_INTERVAL = 60  # seconds

# Komodo API — used to auto-register the onboarded host as a Server (Core -> periphery inbound).
KOMODO_CORE_URL = os.environ.get("KOMODO_CORE_URL", "http://komodo-core:9120").rstrip("/")
KOMODO_API_KEY = os.environ.get("KOMODO_API_KEY", "")
KOMODO_API_SECRET = os.environ.get("KOMODO_API_SECRET", "")

# Alertmanager — the single notification hub (SMTP). Komodo has no native e-mail endpoint, so its
# Custom alerter POSTs here (/alert/komodo, internal only) and we relay to Alertmanager's v2 API.
ALERTMANAGER_URL = os.environ.get("ALERTMANAGER_URL", "http://alertmanager:9093").rstrip("/")

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
GET_RE = re.compile(r"^/provisioning/([^/]+)/install\.sh$")
BURN_RE = re.compile(r"^/provisioning/([^/]+)/burn$")
COMPLETE_RE = re.compile(r"^/provisioning/([^/]+)/complete$")
ALERT_RE = re.compile(r"^/alert/komodo$")  # internal only (Traefik routes /provisioning only)
# mesh_ip is used to build the Server address Core will dial — only accept our mesh range.
MESH_IP_RE = re.compile(r"^100\.64\.\d{1,3}\.\d{1,3}$")
NAME_BAD = re.compile(r"[^A-Za-z0-9._-]")


# App deploy config baked into auto-created Repo resources (SEGCORE defaults; env-overridable).
APP_DEPLOY_ROLE = os.environ.get("APP_DEPLOY_ROLE", "segcore")
APP_GIT_PROVIDER = os.environ.get("APP_GIT_PROVIDER", "github.com")
APP_GIT_ACCOUNT = os.environ.get("APP_GIT_ACCOUNT", "jquelhas")
APP_GIT_REPO = os.environ.get("APP_GIT_REPO", "jquelhas/GIMSv2")
APP_GIT_BRANCH = os.environ.get("APP_GIT_BRANCH", "main")
APP_PATH = os.environ.get("APP_PATH", "/apps/GIMSv2")
APP_ON_PULL = os.environ.get("APP_ON_PULL", "./scripts/update.sh")
APP_TAG = os.environ.get("APP_TAG", "segcore")
# Seeds the Repo's `environment`, which Komodo writes to <APP_PATH>/.env (0600) before each on_pull.
# Absent file -> environment stays empty -> Komodo writes no file at all (the pre-existing
# behaviour), so a missing template degrades to "operator manages the .env by hand".
APP_ENV_TEMPLATE = os.environ.get("APP_ENV_TEMPLATE", "/app/app-env.template")
_TAG_ID = {}


def host_upper(hostname):
    """Host name as it appears in per-host Variable names: DEMO, PROD_2."""
    return re.sub(r"[^A-Z0-9_]", "_", hostname.upper())


def render_app_env(hostname, mesh_ip):
    """Render the app .env template for one host. Returns "" if there is no template.

    Only substitutes {{MESH_IP}} / {{HOSTNAME}} / {{HOST_UPPER}}: the [[NAME]] placeholders must
    survive untouched, since Core (Variables / config secrets) and that host's periphery ([secrets])
    resolve them at deploy time. Any remaining CHANGE_ME is intentional — the on_pull guard refuses
    to deploy while the .env still has unresolved placeholders.
    """
    try:
        with open(APP_ENV_TEMPLATE, "r", encoding="utf-8") as f:
            template = f.read()
    except OSError:
        return ""
    return (
        template.replace("{{MESH_IP}}", mesh_ip)
        .replace("{{HOSTNAME}}", hostname)
        .replace("{{HOST_UPPER}}", host_upper(hostname))
    )


def komodo_api(path, body):
    """POST to the Komodo API. Returns (status_int, parsed_or_text). status 0 = transport error."""
    if not (KOMODO_API_KEY and KOMODO_API_SECRET):
        return 0, "no api creds"
    req = urllib.request.Request(
        f"{KOMODO_CORE_URL}/{path}",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": KOMODO_API_KEY,
            "X-Api-Secret": KOMODO_API_SECRET,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"null")
            except ValueError:
                return r.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read() or b"").decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def _exists_err(detail):
    return any(w in str(detail).lower() for w in ("exist", "duplicate", "taken", "unique"))


def _oid(resp):
    return resp.get("_id", {}).get("$oid") if isinstance(resp, dict) else None


def komodo_find_id(list_path, name):
    st, resp = komodo_api(list_path, {})
    if isinstance(resp, list):
        for r in resp:
            if r.get("name") == name:
                return r.get("id") or _oid(r)
    return None


def komodo_register_server(name, mesh_ip):
    """Create the Server (idempotent). Returns (server_id or None, detail)."""
    st, resp = komodo_api(
        "write/CreateServer",
        {"name": name, "config": {"address": f"https://{mesh_ip}:8120", "enabled": True}},
    )
    if _oid(resp):
        return _oid(resp), "created"
    if _exists_err(resp):
        return komodo_find_id("read/ListServers", name), "already registered"
    return None, f"http {st}: {str(resp)[:200]}"


def komodo_ensure_tag(name):
    if name in _TAG_ID:
        return _TAG_ID[name]
    st, resp = komodo_api("write/CreateTag", {"name": name})
    tid = _oid(resp) or komodo_find_id("read/ListTags", name)
    if tid:
        _TAG_ID[name] = tid
    return tid


# Secrets that belong to one host, generated here at onboarding as Komodo Variables named
# <HOST>_<SUFFIX> and referenced from the app .env template as [[{{HOST_UPPER}}_<SUFFIX>]].
#
# Generated at onboarding and NEVER regenerated. The app .env is rewritten on every deploy, so a
# value generated at boot-time-if-missing would change on every deploy — logging everyone out
# (JWT_SECRET) or, worse, disagreeing with the password the Postgres cluster was initialised with
# (DB_PASSWORD), which locks the app out of its own database.
#
# Per host rather than fleet-wide for different reasons each:
#   JWT_SECRET   the app backends are PUBLIC, so one shared signing key would let a token minted on
#                any host authenticate as admin on every other tenant. Safe to differ per host now
#                that TENANT_CONFIG_KEY carries the at-rest encryption: rotating the signing key ends
#                sessions but does not make stored ciphertext unreadable.
#   DB_PASSWORD  the password lives inside the Postgres cluster, not in this file. A fleet-wide value
#                can only ever be right by luck; per host, the mismatch is impossible by construction.
HOST_SECRETS = (
    ("JWT_SECRET", "JWT signing secret"),
    ("DB_PASSWORD", "Postgres password"),
)


def komodo_ensure_host_secrets(hostname):
    """Create this host's own secrets as Komodo Variables, once each. Returns (ok, detail)."""
    made, kept, failed = [], [], []
    for suffix, label in HOST_SECRETS:
        var = f"{host_upper(hostname)}_{suffix}"
        st, resp = komodo_api(
            "write/CreateVariable",
            {
                "name": var,
                "value": secrets.token_hex(32),
                "description": f"{label} for {hostname} (generated at onboarding)",
                "is_secret": True,
            },
        )
        if isinstance(resp, dict) and resp.get("name") == var:
            made.append(var)
        elif _exists_err(resp):
            kept.append(var)      # never overwrite an existing one: the host is already using it
        else:
            failed.append(f"{var}: http {st} {str(resp)[:120]}")
    if failed:
        return False, "; ".join(failed)
    return True, f"created {len(made)}, kept {len(kept)}"


def komodo_register_repo(server_id, name, mesh_ip=""):
    """Create the per-host Repo (idempotent) + tag it. Returns (ok, detail).
    Repo is named "<APP_TAG>-<host>" so both name-pattern (e.g. segcore-*) and tag batches work."""
    repo_name = name if name.startswith(f"{APP_TAG}-") else f"{APP_TAG}-{name}"
    cfg = {
        "server_id": server_id,
        "git_provider": APP_GIT_PROVIDER,
        "git_https": True,
        "git_account": APP_GIT_ACCOUNT,
        "repo": APP_GIT_REPO,
        "branch": APP_GIT_BRANCH,
        "path": APP_PATH,
        "on_pull": {"path": "", "command": APP_ON_PULL, "shell_mode": True},
        "webhook_enabled": False,
        # Komodo writes this to <path>/.env (0600) before running on_pull. Empty -> no file written.
        "environment": render_app_env(name, mesh_ip),
        "env_file_path": ".env",
        "skip_secret_interp": False,
    }
    st, resp = komodo_api("write/CreateRepo", {"name": repo_name, "config": cfg})
    ok = bool(_oid(resp)) or _exists_err(resp)
    if not ok:
        return False, f"http {st}: {str(resp)[:200]}"
    tid = komodo_ensure_tag(APP_TAG)
    if tid:
        komodo_api("write/UpdateResourceMeta", {"target": {"type": "Repo", "id": repo_name}, "tags": [tid]})
    return True, "created"


def entry_role(uuid):
    d = entry_dir(uuid)
    try:
        with open(os.path.join(d, "meta.json"), "r", encoding="utf-8") as f:
            return json.load(f).get("role", "")
    except (OSError, ValueError, TypeError):
        return ""


# --- Prometheus http_sd: derive scrape targets from the Komodo server list ---
MESH_IP_ANY = re.compile(r"(100\.64\.\d{1,3}\.\d{1,3})")
_SD_CACHE = {}  # port -> last good [ {targets, labels} ]
_SD_LOCK = threading.Lock()


def komodo_list_servers():
    """Return the Komodo server list, or None on any failure."""
    if not (KOMODO_API_KEY and KOMODO_API_SECRET):
        return None
    req = urllib.request.Request(
        f"{KOMODO_CORE_URL}/read/ListServers",
        data=b"{}",
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": KOMODO_API_KEY,
            "X-Api-Secret": KOMODO_API_SECRET,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:  # noqa: BLE001
        return None


def sd_targets(port):
    """http_sd target groups for a given port, derived from Komodo servers whose address is a
    mesh IP. Falls back to the last good result if Komodo is unreachable."""
    servers = komodo_list_servers()
    if servers is None:
        with _SD_LOCK:
            return _SD_CACHE.get(port, [])
    groups = []
    for s in servers:
        addr = (s.get("info") or {}).get("address") or (s.get("config") or {}).get("address", "")
        m = MESH_IP_ANY.search(addr or "")
        if not m:
            continue
        groups.append(
            {"targets": [f"{m.group(1)}:{port}"], "labels": {"app": "gims", "host": s.get("name", "")}}
        )
    with _SD_LOCK:
        _SD_CACHE[port] = groups
    return groups


SD_PORTS = {"/sd/gims/backend": 3000, "/sd/gims/postgresql": 9187}


# --- Komodo -> Alertmanager relay ---
# Komodo's Custom alerter POSTs the serialized Alert. We map it to an Alertmanager v2 alert and
# forward it, so infra alerts (server unreachable, cpu/mem/disk, container state) land in the same
# inbox as the app (vmalert) alerts. Kept deliberately tolerant of Komodo's exact JSON shape.
_LEVEL_SEVERITY = {"Critical": "critical", "Warning": "warning", "Ok": "info"}


def _rfc3339(epoch_s):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_s))


def komodo_alert_to_am(payload):
    """Map a Komodo Alert dict to a single Alertmanager v2 alert (as a 1-item list)."""
    if not isinstance(payload, dict):
        return []
    level = str(payload.get("level", "Warning"))
    resolved = bool(payload.get("resolved"))
    data = payload.get("data") or {}
    dtype = str(data.get("type") or "KomodoAlert")
    ddata = data.get("data") if isinstance(data.get("data"), dict) else {}
    target = payload.get("target") or {}
    server = str(ddata.get("name") or target.get("id") or "unknown")
    # Human-readable one-liner from whatever fields the variant carries.
    detail = ", ".join(
        f"{k}={v}" for k, v in ddata.items() if k not in ("id", "name") and not isinstance(v, (dict, list))
    )
    ts = payload.get("ts")
    starts = _rfc3339(ts / 1000.0) if isinstance(ts, (int, float)) else _rfc3339(time.time())
    # Active alerts get a far-future endsAt so Alertmanager doesn't auto-resolve between Komodo's
    # state-change POSTs; a resolve POST sets endsAt=now to clear it.
    ends = _rfc3339(time.time()) if resolved else _rfc3339(time.time() + 6 * 3600)
    return [{
        "labels": {
            "alertname": f"Komodo{dtype}",
            "severity": _LEVEL_SEVERITY.get(level, "warning"),
            "source": "komodo",
            "type": dtype,
            "server": server,
        },
        "annotations": {
            "summary": f"{dtype} on {server} ({level})",
            "description": detail or f"Komodo alert {dtype} on {server}.",
        },
        "startsAt": starts,
        "endsAt": ends,
    }]


def post_alertmanager(alerts):
    """POST alerts to Alertmanager's v2 API. Returns (ok, detail)."""
    if not alerts:
        return True, "nothing to send"
    req = urllib.request.Request(
        f"{ALERTMANAGER_URL}/api/v2/alerts",
        data=json.dumps(alerts).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300, f"http {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"http {e.code}: {(e.read() or b'').decode(errors='replace')[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


# --- Per-container metrics exporter: reuse the stats Komodo/Periphery already collects ---
# Komodo's read/ListDockerContainers returns each container's `stats` (the docker-stats snapshot:
# cpu_perc, mem_perc, mem_usage, net_io, block_io, pids). We translate that to Prometheus so VM can
# scrape it — no cAdvisor/agent on the hosts. Values are unit strings, so we parse them to numbers.
_SIZE_RE = re.compile(r"([0-9.]+)\s*([A-Za-z]+)")
_UNITS = {
    "B": 1.0, "kB": 1e3, "KB": 1e3, "KiB": 1024.0, "MB": 1e6, "MiB": 1024.0 ** 2,
    "GB": 1e9, "GiB": 1024.0 ** 3, "TB": 1e12, "TiB": 1024.0 ** 4, "PB": 1e15, "PiB": 1024.0 ** 5,
}


def _size(s):
    m = _SIZE_RE.search(s or "")
    return float(m.group(1)) * _UNITS.get(m.group(2), 1.0) if m else None


def _pair(s):
    parts = (s or "").split("/")
    return (_size(parts[0]), _size(parts[1])) if len(parts) == 2 else (None, None)


def _pct(s):
    try:
        return float(str(s).replace("%", "").strip())
    except (ValueError, AttributeError):
        return None


def _lbl(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


def komodo_list_containers(server_name):
    _st, resp = komodo_api("read/ListDockerContainers", {"server": server_name})
    return resp if isinstance(resp, list) else None


# NOTE: no cpu_percent here on purpose. Komodo's docker-stats `cpu_perc` is delta-based and comes
# back unreliable/stale (observed stuck at ~24% while the host was idle at 0.3%), so we don't collect
# it. mem/net/block/pids are absolute values and are trustworthy. Accurate per-container CPU would
# need cAdvisor (container_cpu_usage_seconds_total + rate()).
_CONTAINER_FAMILIES = [
    ("komodo_container_running", "gauge", "1 if the container state is running"),
    ("komodo_container_mem_percent", "gauge", "Memory usage percent"),
    ("komodo_container_mem_used_bytes", "gauge", "Memory used in bytes"),
    ("komodo_container_mem_limit_bytes", "gauge", "Memory limit in bytes"),
    ("komodo_container_pids", "gauge", "Number of PIDs"),
    ("komodo_container_net_receive_bytes_total", "counter", "Network bytes received (cumulative)"),
    ("komodo_container_net_transmit_bytes_total", "counter", "Network bytes transmitted (cumulative)"),
    ("komodo_container_block_read_bytes_total", "counter", "Block I/O bytes read (cumulative)"),
    ("komodo_container_block_write_bytes_total", "counter", "Block I/O bytes written (cumulative)"),
]


def container_metrics_text():
    """Prometheus exposition of per-container stats across all Komodo servers."""
    samples = {name: [] for name, _t, _h in _CONTAINER_FAMILIES}
    servers = komodo_list_servers() or []
    for s in servers:
        host = s.get("name", "")
        conts = komodo_list_containers(host)
        if not isinstance(conts, list):
            continue  # server unreachable / no data — skip
        for c in conts:
            name = c.get("name", "")
            # The secaudit couriers exit on purpose after every collection, so they would sit here
            # as permanently not-running rows — an always-red line on the containers dashboard,
            # which is how operators learn to ignore red. Their real state is reported by
            # secaudit_host_enrolled / secaudit_report_age_seconds, where "exited" is correct.
            # Filter on the name, not a label: ContainerListItem does not carry labels.
            if name.startswith("secaudit-"):
                continue
            lbl = f'host="{_lbl(host)}",name="{_lbl(name)}"'
            samples["komodo_container_running"].append((lbl, 1 if c.get("state") == "running" else 0))
            st = c.get("stats") or {}
            if not isinstance(st, dict):
                continue

            def add(metric, val):
                if val is not None:
                    samples[metric].append((lbl, val))

            add("komodo_container_mem_percent", _pct(st.get("mem_perc")))
            used, limit = _pair(st.get("mem_usage"))
            add("komodo_container_mem_used_bytes", used)
            add("komodo_container_mem_limit_bytes", limit)
            try:
                add("komodo_container_pids", int(st.get("pids")))
            except (ValueError, TypeError):
                pass
            rx, tx = _pair(st.get("net_io"))
            add("komodo_container_net_receive_bytes_total", rx)
            add("komodo_container_net_transmit_bytes_total", tx)
            rd, wr = _pair(st.get("block_io"))
            add("komodo_container_block_read_bytes_total", rd)
            add("komodo_container_block_write_bytes_total", wr)

    out = []
    for name, typ, help_ in _CONTAINER_FAMILIES:
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {typ}")
        for lbl, val in samples[name]:
            out.append(f"{name}{{{lbl}}} {val}")
    return "\n".join(out) + "\n"


# --- Security auditor exporter -----------------------------------------------------------------
# Renders the state written by scripts/security-*.sh (mounted read-only at /security) as Prometheus
# metrics, APPLYING POLICY AT SCRAPE TIME: the expected-ports baseline and the suppression list are
# evaluated here, on every scrape, not baked in when the scan ran. So fixing a baseline entry or
# letting a suppression lapse takes effect within one scrape interval (~60s) instead of at the next
# scan — which for a weekly scan would be up to a week.
#
# This is deliberately the least privileged code in this file: it only parses local files, makes no
# outbound call and takes no attacker-controlled input. The mount is :ro, so a compromise of this
# (the one publicly-routed process in the stack) cannot forge or erase audit results.
SECURITY_DIR = os.path.realpath(os.environ.get("SECURITY_DIR", "/security"))
SECAUDIT_MAX_SUPPRESSION_DAYS = int(os.environ.get("SECAUDIT_MAX_SUPPRESSION_DAYS", "180"))
_SEC_MAX_SERIES = 500  # per family. One degenerate scan must not fill a 60d TSDB on a 14GB disk.
_SEC_CACHE = {}  # rel path -> ((mtime_ns, size), parsed)
_SEC_LOCK = threading.Lock()

# Max age per scan before it counts as stale. Emitted as a metric (secaudit_scan_max_age_seconds)
# so ONE alert rule covers every cadence instead of one rule per scan. Only budgets for scans that
# have actually reported are emitted, so the set grows as the later phases land.
_SCAN_BUDGETS = {
    "discovery": 900, "listeners": 900, "docker_ports": 900, "drift": 900,  # 5-minute sensors
    "collect": 129600, "ports": 129600, "tls": 129600,                      # daily -> 36h
    "web": 1036800,                                                         # weekly -> 12d
}
# "image" covers a deliberately pinned old image: a frozen version kept for compatibility is a
# decision, and it should be suppressible with a date and an owner like any other.
_SUPPRESSION_KINDS = ("port", "tls", "nuclei", "image", "bench", "lynis")


def _sec_load(rel):
    """mtime+size cached load of a JSON/TOML file under SECURITY_DIR. None on any error.

    Returning None (rather than {}) is load-bearing: the caller turns it into
    secaudit_exporter_state_error, so "no data" can never be read as "no findings".
    """
    path = os.path.join(SECURITY_DIR, rel)
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        with _SEC_LOCK:
            _SEC_CACHE.pop(rel, None)
        return None
    with _SEC_LOCK:
        hit = _SEC_CACHE.get(rel)
    if hit and hit[0] == key:
        return hit[1]
    try:
        if rel.endswith(".toml"):
            with open(path, "rb") as f:
                val = tomllib.load(f)
        else:
            with open(path, "r", encoding="utf-8") as f:
                val = json.load(f)
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None
    with _SEC_LOCK:
        _SEC_CACHE[rel] = (key, val)
    return val


def _sec_load_ndjson(rel):
    """mtime+size cached load of a host report. Returns a list of records, or None."""
    path = os.path.join(SECURITY_DIR, rel)
    try:
        st = os.stat(path)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        with _SEC_LOCK:
            _SEC_CACHE.pop(rel, None)
        return None
    with _SEC_LOCK:
        hit = _SEC_CACHE.get(rel)
    if hit and hit[0] == key:
        return hit[1]
    recs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
    except (OSError, ValueError):
        return None
    with _SEC_LOCK:
        _SEC_CACHE[rel] = (key, recs)
    return recs


def sec_budget(budgets, host, key):
    """Per-(host, section) budget, falling back to a generous default so a newly enrolled machine
    does not page on day one, before anyone has looked at it."""
    h = (budgets.get("hosts") or {}).get(host) or {}
    if key in h:
        return h[key]
    return (budgets.get("defaults") or {}).get(key, 0)

def _sec_scope(addr):
    """Classify a bind address. This is the whole point of the local sensor: 0.0.0.0 and the public
    IP are exposed to whatever the external firewall permits, the mesh IP and loopback are not."""
    # "*" is what ss prints for a dual-stack wildcard socket; without it the Komodo agent's
    # listener was classified "public", which is the right verdict for the wrong reason.
    if addr in ("0.0.0.0", "::", "*", ""):
        return "wildcard"
    if addr.startswith("127.") or addr == "::1":
        return "loopback"
    # 100.64.0.0/16 is the Headscale IPv4 pool; fd7a:115c:a1e0::/48 is Tailscale's ULA prefix.
    if addr.startswith("100.64.") or addr.startswith("fd7a:"):
        return "mesh"
    return "public"


def sec_expected(baseline, role, host, perspective):
    """Effective expected set for (role, host, perspective): role default, plus per-host extra_*,
    minus per-host remove_*. `known` is False when the role has no defaults at all — the caller
    must then NOT flag anything, or an unknown role produces an alert per open port."""
    d = ((baseline.get("defaults") or {}).get(role) or {}).get(perspective) or {}
    h = ((baseline.get("hosts") or {}).get(host) or {}).get(perspective) or {}
    out = {"known": bool(d)}
    for proto in ("tcp", "udp"):
        allowed = set(d.get(proto) or [])
        allowed |= set(h.get("extra_" + proto) or [])
        allowed -= set(h.get("remove_" + proto) or [])
        out[proto] = allowed
    req = set(d.get("required_tcp") or []) | set(h.get("extra_required_tcp") or [])
    out["required_tcp"] = req - set(h.get("remove_tcp") or [])
    return out


def sec_suppressions():
    """Parse suppressions.toml into (valid, invalid). FAIL-CLOSED: anything questionable lands in
    `invalid`, which suppresses NOTHING and raises secaudit_suppression_invalid. An operator who
    believes they silenced a finding and did not is the worst possible outcome."""
    doc = _sec_load("suppressions.toml")
    if doc is None:
        return [], [], False
    valid, invalid = [], []
    now = time.time()
    horizon = now + SECAUDIT_MAX_SUPPRESSION_DAYS * 86400
    for e in doc.get("suppress") or []:
        kind = str(e.get("kind", ""))
        host = str(e.get("host", ""))
        match = str(e.get("match", ""))
        raw = e.get("expires")
        ent = {"kind": kind or "?", "host": host or "?", "match": match or "?",
               "owner": str(e.get("owner", "")), "ticket": str(e.get("ticket", ""))}
        why = ""
        if kind not in _SUPPRESSION_KINDS:
            why = "unknown_kind"
        elif not host or not match:
            why = "missing_host_or_match"
        elif not str(e.get("reason", "")).strip():
            why = "missing_reason"
        elif not ent["owner"].strip():
            why = "missing_owner"
        else:
            try:
                d = datetime.datetime.strptime(str(raw), "%Y-%m-%d")
                # End of that day, UTC: an entry expiring "today" is still valid all day.
                exp = d.replace(tzinfo=datetime.timezone.utc).timestamp() + 86400
            except (TypeError, ValueError):
                why = "bad_expires"
                exp = 0.0
            if not why and exp <= now:
                why = "expired"
            elif not why and exp > horizon:
                why = "beyond_horizon"   # kills "expires = 2099-01-01"
            if not why:
                ent["expires"] = exp
                valid.append(ent)
                continue
        ent["invalid_reason"] = why
        invalid.append(ent)
    return valid, invalid, True


def _sec_suppressed(valid, used, kind, host, key):
    """(is_suppressed, expiry). Globs on both host and key, so one entry can cover a fleet or a
    whole image. Records which entries matched, so unused ones can be reported as stale."""
    for i, e in enumerate(valid):
        if e["kind"] != kind:
            continue
        if fnmatch.fnmatch(host, e["host"]) and fnmatch.fnmatch(key, e["match"]):
            used.add(i)
            return True, e["expires"]
    return False, None


_SECURITY_FAMILIES = [
    # Lifecycle — the anti-silent-failure core. A stale scan is not a clean scan.
    ("secaudit_scan_last_run_timestamp_seconds", "gauge", "Unix time of the last run of a scan"),
    ("secaudit_scan_last_success_timestamp_seconds", "gauge", "Unix time of the last SUCCESSFUL run"),
    ("secaudit_scan_last_status", "gauge", "1 if the last run of a scan succeeded"),
    ("secaudit_scan_duration_seconds", "gauge", "Duration of the last run of a scan"),
    ("secaudit_scan_targets", "gauge", "Targets covered by the last run of a scan"),
    ("secaudit_scan_max_age_seconds", "gauge", "Age at which a scan's results count as stale"),
    ("secaudit_scan_skipped_total", "counter", "Times a scan skipped itself, by reason"),
    ("secaudit_discovery_ok", "gauge", "1 if target discovery from Komodo succeeded"),
    ("secaudit_discovery_shrunk", "gauge", "1 if discovery returned far fewer targets than before"),
    ("secaudit_discovery_targets", "gauge", "Number of discovered targets"),
    ("secaudit_target_incomplete", "gauge", "1 if a target is missing a field needed to audit it"),
    ("secaudit_host_scannable", "gauge", "1 if the host is reachable for auditing"),
    ("secaudit_exporter_state_error", "gauge", "1 if a state or policy file is missing/unparseable"),
    ("secaudit_findings_truncated", "gauge", "1 if a family hit the series cap and was truncated"),
    # Perimeter
    ("secaudit_listener", "gauge", "A listening socket, by bind address and scope"),
    ("secaudit_docker_published_port", "gauge", "A published container port, by bind address"),
    ("secaudit_port_open", "gauge", "An observed open/exposed port"),
    ("secaudit_port_unexpected", "gauge", "An exposed port that is not in the baseline"),
    ("secaudit_port_missing", "gauge", "A baseline-required port that was not observed"),
    ("secaudit_unexpected_ports", "gauge", "Count of unexpected ports per host and perspective"),
    # Host bundle: enrolment and freshness. "not enrolled" is a DELIBERATE state (the fleet is
    # enrolled one machine at a time) and is kept separate from staleness on purpose, so it never
    # alerts.
    ("secaudit_host_enrolled", "gauge", "1 if the host has the audit bundle installed and reporting"),
    ("secaudit_report_age_seconds", "gauge", "Age of the host's last audit report"),
    ("secaudit_report_partial", "gauge", "1 if the host's last report was cut short"),
    ("secaudit_host_step_error", "gauge", "1 if a scanner step failed on the host"),
    ("secaudit_tool_version_info", "gauge", "Installed scanner version, as a label"),
    # OS hardening (lynis)
    ("secaudit_lynis_finding", "gauge", "A lynis warning or suggestion"),
    ("secaudit_lynis_findings", "gauge", "Count of lynis findings per section and severity"),
    ("secaudit_lynis_findings_over_budget", "gauge", "Findings above the committed budget"),
    ("secaudit_lynis_hardening_index", "gauge", "Lynis hardening index, 0-100 (trend only)"),
    ("secaudit_packages_vulnerable", "gauge", "Packages with a known vulnerability, per lynis"),
    # CIS Docker benchmark
    ("secaudit_bench_failed", "gauge", "A failed CIS Docker Benchmark check"),
    ("secaudit_bench_failures", "gauge", "Count of benchmark failures per section"),
    ("secaudit_bench_failures_over_budget", "gauge", "Failures above the committed budget"),
    ("secaudit_bench_score", "gauge", "docker-bench-security score (trend only)"),
    # Image CVEs. Counts only — per-CVE detail lives in the on-disk archive, never in the TSDB.
    # Image CVE scanning moved to the application's CI on 2026-09-08 (docs/CI-IMAGE-SCANNING.md):
    # the fix lives in a repository, not on a host, and alerting where nobody can act is how an
    # alert stream gets ignored. What the fleet still answers is the question CI cannot — is what
    # is RUNNING what we think we shipped — and image age is the cheap proxy for it. A running
    # image built months ago has stopped receiving base-layer patches, whether that is a stale pin
    # or a deploy that quietly never happened.
    ("secaudit_running_image_age_seconds", "gauge",
     "Age of an image backing a running container, from Komodo's own metadata"),
    ("secaudit_running_images", "gauge", "Images backing at least one running container"),
    # Perimeter cross-scan, measured FROM a host
    ("secaudit_perimeter_port_open", "gauge", "A port found open by the cross-scan"),
    ("secaudit_perimeter_scan_timestamp_seconds", "gauge", "When the cross-scan last ran"),
    # Internal-service checklist drift
    ("secaudit_internal_name_misconfigured", "gauge",
     "1 if an internal name is missing from DNS/step-ca, or a step-ca entry has no router"),
    # Suppression hygiene
    ("secaudit_suppression_expiry_timestamp_seconds", "gauge", "Expiry of a valid suppression"),
    ("secaudit_suppression_invalid", "gauge", "1 if a suppression entry is invalid (suppresses nothing)"),
    ("secaudit_suppression_stale", "gauge", "1 if a valid suppression matches no current finding"),
]


def security_metrics_text():
    """Prometheus exposition of the security auditor's state.

    INVARIANT: per-finding series are emitted only while the finding exists, so an alert resolves
    when a scan clears it; count series are always emitted, 0 when empty, so a dashboard never
    reads `No data` and "clean" is never confused with "exporter broken".
    """
    samples = {name: [] for name, _t, _h in _SECURITY_FAMILIES}
    errors = []

    def add(metric, labels, value):
        samples[metric].append((labels, value))

    def lbl(**kw):
        return ",".join(f'{k}="{_lbl(v)}"' for k, v in kw.items())

    # ---- lifecycle ----------------------------------------------------------------------------
    status = _sec_load("state/scan-status.json")
    if status is None:
        errors.append("state/scan-status.json")
    else:
        for entry in (status.get("scans") or {}).values():
            scan, host = entry.get("scan", ""), entry.get("host", "")
            l = lbl(scan=scan, host=host)
            if entry.get("last_run") is not None:
                add("secaudit_scan_last_run_timestamp_seconds", l, entry["last_run"])
            if entry.get("last_success") is not None:
                add("secaudit_scan_last_success_timestamp_seconds", l, entry["last_success"])
            if entry.get("status") is not None:
                add("secaudit_scan_last_status", l, int(entry["status"]))
            if entry.get("duration") is not None:
                add("secaudit_scan_duration_seconds", l, entry["duration"])
            if entry.get("targets") is not None:
                # host is part of the series, not just scan: from phase 2 the collect scan runs
                # per host, and without it those runs would write conflicting samples to one
                # series.
                add("secaudit_scan_targets", l, entry["targets"])
            if scan in _SCAN_BUDGETS:
                add("secaudit_scan_max_age_seconds", lbl(scan=scan), _SCAN_BUDGETS[scan])
        for key, count in (status.get("skips") or {}).items():
            scan, _, reason = key.partition("|")
            add("secaudit_scan_skipped_total", lbl(scan=scan, reason=reason), count)

    disc = _sec_load("state/discovery.json")
    if disc is None:
        errors.append("state/discovery.json")
    else:
        add("secaudit_discovery_ok", "", 1 if disc.get("ok") else 0)
        add("secaudit_discovery_shrunk", "", 1 if disc.get("shrunk") else 0)
        add("secaudit_discovery_targets", "", disc.get("count", 0))
        for inc in disc.get("incomplete") or []:
            add("secaudit_target_incomplete",
                lbl(host=inc.get("host", ""), field=inc.get("field", "")), 1)

    targets = _sec_load("state/targets.json")
    hosts = {}
    if targets is None:
        errors.append("state/targets.json")
    else:
        for t in targets.get("targets") or []:
            hosts[t.get("host", "")] = t
            add("secaudit_host_scannable", lbl(host=t.get("host", "")), t.get("scannable", 0))

    baseline = _sec_load("baseline/ports.toml")
    if baseline is None:
        errors.append("baseline/ports.toml")
        baseline = {}

    valid_sup, invalid_sup, sup_ok = sec_suppressions()
    if not sup_ok:
        errors.append("suppressions.toml")
    used_sup = set()

    # ---- observed exposure, per host ----------------------------------------------------------
    # observed[host] = {(proto, port): (bind, scope)} for scopes that mean "reachable from off-box".
    observed = {}
    evaluated = set()  # hosts we have fresh data for; only these get baseline verdicts

    listeners = _sec_load("state/listeners.json")
    if listeners is None:
        errors.append("state/listeners.json")
    else:
        host = listeners.get("host", "manager")
        evaluated.add(host)
        for s in listeners.get("listeners") or []:
            scope = _sec_scope(s.get("addr", ""))
            add("secaudit_listener",
                lbl(host=host, proto=s.get("proto", ""), port=s.get("port", ""),
                    bind=s.get("addr", ""), scope=scope, process=s.get("process", "")), 1)
            if scope in ("wildcard", "public"):
                # setdefault, not assignment: a service bound on both 0.0.0.0 and :: is ONE
                # finding, not two. It also keeps the suppression key (proto/port) 1:1 with the
                # finding, so one suppression entry covers both families.
                observed.setdefault(host, {}).setdefault(
                    (s.get("proto", ""), s.get("port", 0)), (s.get("addr", ""), scope))

    dports = _sec_load("state/docker-ports.json")
    if dports is None:
        errors.append("state/docker-ports.json")
    else:
        for host, hd in (dports.get("hosts") or {}).items():
            if hd.get("ok"):
                evaluated.add(host)
            for p in hd.get("ports") or []:
                scope = _sec_scope(p.get("addr", ""))
                add("secaudit_docker_published_port",
                    lbl(host=host, proto=p.get("proto", ""), port=p.get("port", ""),
                        bind=p.get("addr", ""), scope=scope,
                        container=p.get("container", "")), 1)
                if scope in ("wildcard", "public"):
                    observed.setdefault(host, {}).setdefault(
                        (p.get("proto", ""), p.get("port", 0)), (p.get("addr", ""), scope))

    # ---- host bundle reports ------------------------------------------------------------------
    # Collected through the couriers by scripts/security-collect.sh. This is where the OS-level
    # findings enter: lynis, the CIS benchmark, image CVEs, the non-Docker listeners, and the
    # perimeter cross-scan.
    budgets = _sec_load("baseline/bench.toml")
    if budgets is None:
        errors.append("baseline/bench.toml")
        budgets = {}
    collect = _sec_load("state/collect.json")
    if collect is None:
        errors.append("state/collect.json")
    for host, st in ((collect or {}).get("hosts") or {}).items():
        status = st.get("status", "")
        if status == "not_enrolled":
            # Deliberate, not a fault: emit the fact and nothing else. No staleness, no alert.
            add("secaudit_host_enrolled", lbl(host=host), 0)
            continue
        recs = _sec_load_ndjson(f"state/hosts/{host}.ndjson")
        if recs is None:
            add("secaudit_host_enrolled", lbl(host=host), 0)
            continue
        add("secaudit_host_enrolled", lbl(host=host), 1)

        def rec(kind):
            return [r for r in recs if r.get("k") == kind]

        meta = (rec("meta") or [{}])[0]
        end = (rec("end") or [{}])[-1]
        if meta.get("ts"):
            add("secaudit_report_age_seconds", lbl(host=host), int(time.time() - meta["ts"]))
        add("secaudit_report_partial", lbl(host=host), 0 if end.get("ok") else 1)
        for r in rec("tool"):
            add("secaudit_tool_version_info",
                lbl(host=host, tool=r.get("name", ""), version=r.get("version", "")), 1)
        for r in rec("tool_error"):
            add("secaudit_host_step_error", lbl(host=host, tool=r.get("tool", "")), 1)

        # Listeners seen from INSIDE the host: the only view that includes non-Docker services
        # (sshd, the Komodo agent, tailscaled) and the only one with process attribution.
        listens = rec("listen")
        if listens:
            evaluated.add(host)
            for r in listens:
                scope = _sec_scope(r.get("addr", ""))
                add("secaudit_listener",
                    lbl(host=host, proto=r.get("proto", ""), port=r.get("port", ""),
                        bind=r.get("addr", ""), scope=scope, process=r.get("process", "")), 1)
                if scope in ("wildcard", "public"):
                    observed.setdefault(host, {}).setdefault(
                        (r.get("proto", ""), r.get("port", 0)), (r.get("addr", ""), scope))

        # --- lynis ---
        lyn_counts = {}
        for r in rec("lynis"):
            sev, section = r.get("severity", ""), r.get("section", "")
            key = f"{r.get('test_id', '')}/{r.get('detail', '')}"
            sup, _e = _sec_suppressed(valid_sup, used_sup, "lynis", host, key)
            sl = "1" if sup else "0"
            add("secaudit_lynis_finding",
                lbl(host=host, test_id=r.get("test_id", ""), section=section,
                    severity=sev, detail=r.get("detail", "")[:60], suppressed=sl), 1)
            lyn_counts[(section, sev, sl)] = lyn_counts.get((section, sev, sl), 0) + 1
        for (section, sev, sl), n in sorted(lyn_counts.items()):
            add("secaudit_lynis_findings",
                lbl(host=host, section=section, severity=sev, suppressed=sl), n)
        for sev in ("warning", "suggestion"):
            unsup = sum(n for (s, v, sl), n in lyn_counts.items() if v == sev and sl == "0")
            budget = sec_budget(budgets, host, f"lynis_{sev}")
            add("secaudit_lynis_findings_over_budget",
                lbl(host=host, severity=sev), max(0, unsup - budget))
        for r in rec("lynis_meta"):
            add("secaudit_lynis_hardening_index", lbl(host=host), r.get("hardening_index", 0))
        for r in rec("packages"):
            add("secaudit_packages_vulnerable", lbl(host=host), r.get("vulnerable", 0))

        # --- CIS docker benchmark ---
        bench_counts = {}
        for r in rec("bench"):
            section = r.get("section", "")
            sup, _e = _sec_suppressed(valid_sup, used_sup, "bench", host, r.get("id", ""))
            sl = "1" if sup else "0"
            add("secaudit_bench_failed",
                lbl(host=host, id=r.get("id", ""), section=section, suppressed=sl), 1)
            bench_counts[(section, sl)] = bench_counts.get((section, sl), 0) + 1
        for (section, sl), n in sorted(bench_counts.items()):
            add("secaudit_bench_failures", lbl(host=host, section=section, suppressed=sl), n)
        unsup = sum(n for (s, sl), n in bench_counts.items() if sl == "0")
        add("secaudit_bench_failures_over_budget",
            lbl(host=host), max(0, unsup - sec_budget(budgets, host, "bench")))
        for r in rec("bench_meta"):
            add("secaudit_bench_score", lbl(host=host), r.get("score", 0))

        # --- perimeter cross-scan, run FROM this host against the manager ---
        for r in rec("scan_ok"):
            add("secaudit_perimeter_scan_timestamp_seconds",
                lbl(source_host=host, target=r.get("target", "")), meta.get("ts", 0))
        for r in rec("port"):
            target = r.get("target", "")
            # manager_public must match the external firewall allowlist; manager_mesh must be
            # EMPTY, because acl.hujson has no app-host -> manager rule. Anything there is an ACL
            # regression, which is why `expected` is computed rather than assumed.
            persp = "mesh" if target.endswith("_mesh") else "public"
            exp = sec_expected(baseline, "manager", "manager", persp)
            proto = r.get("proto", "tcp")
            ok = exp["known"] and r.get("port") in exp.get(proto, set())
            add("secaudit_perimeter_port_open",
                lbl(source_host=host, target=target, ip=r.get("ip", ""), proto=proto,
                    port=r.get("port", ""), expected="1" if ok else "0"), 1)

    # ---- baseline verdicts (perspective=local) ------------------------------------------------
    # NOTE: `local` measures what is BOUND, not what is reachable. This machine has no host
    # firewall — the external firewall is the authoritative gate and is invisible from here — so
    # this is a DRIFT signal. Reachability is the `public` perspective (nmap, phase 3).
    for host in sorted(evaluated):
        role = (hosts.get(host) or {}).get("role", "")
        exp = sec_expected(baseline, role, host, "local")
        obs = observed.get(host, {})
        unexpected = {"0": 0, "1": 0}
        for (proto, port), (bind, scope) in sorted(obs.items()):
            key = f"local/{proto}/{port}"
            sup, _exp_ts = _sec_suppressed(valid_sup, used_sup, "port", host, key)
            sl = "1" if sup else "0"
            base = lbl(host=host, perspective="local", proto=proto, port=port,
                       bind=bind, scope=scope, suppressed=sl)
            add("secaudit_port_open", base, 1)
            if exp["known"] and port not in exp.get(proto, set()):
                add("secaudit_port_unexpected", base, 1)
                unexpected[sl] += 1
        for sl in ("0", "1"):
            add("secaudit_unexpected_ports",
                lbl(host=host, perspective="local", suppressed=sl), unexpected[sl])
        if exp["known"]:
            seen_tcp = {port for (proto, port) in obs if proto == "tcp"}
            for port in sorted(exp["required_tcp"] - seen_tcp):
                key = f"local/tcp/{port}"
                sup, _e = _sec_suppressed(valid_sup, used_sup, "port", host, key)
                add("secaudit_port_missing",
                    lbl(host=host, perspective="local", proto="tcp", port=port,
                        suppressed="1" if sup else "0"), 1)

    # ---- image freshness across the fleet -----------------------------------------------------
    # Not a vulnerability scan: that moved to the application's CI, where the fix lives. This is the
    # question CI structurally cannot answer — is what is RUNNING what we think we shipped? An
    # image built long ago has stopped receiving base-layer patches, whether because the tag was
    # pinned and never refreshed or because a deploy quietly never happened.
    images = _sec_load("state/images.json")
    if images is None:
        errors.append("state/images.json")
    else:
        now = time.time()
        for host, hd in (images.get("hosts") or {}).items():
            if not hd.get("ok"):
                continue
            used = [i for i in (hd.get("images") or []) if i.get("in_use")]
            add("secaudit_running_images", lbl(host=host), len(used))
            for img in used:
                created = img.get("created")
                if not created:
                    continue
                name = img.get("name", "")
                # A digest-pinned reference is immutable by design and can never be "refreshed"
                # without changing the pin, so ageing it would alert forever on a deliberate choice.
                if "@sha256:" in name:
                    continue
                sup, _e = _sec_suppressed(valid_sup, used_sup, "image", host, name)
                add("secaudit_running_image_age_seconds",
                    lbl(host=host, image=name, suppressed="1" if sup else "0"),
                    max(0, int(now - created)))

    # ---- internal-service checklist drift -----------------------------------------------------
    drift = _sec_load("state/drift.json")
    if drift is None:
        errors.append("state/drift.json")
    else:
        for f in drift.get("findings") or []:
            add("secaudit_internal_name_misconfigured",
                lbl(name=f.get("name", ""), missing=f.get("missing", "")), 1)

    # ---- suppression hygiene ------------------------------------------------------------------
    for i, e in enumerate(valid_sup):
        add("secaudit_suppression_expiry_timestamp_seconds",
            lbl(kind=e["kind"], host=e["host"], key=e["match"],
                owner=e["owner"], ticket=e["ticket"]), int(e["expires"]))
        if i not in used_sup:
            add("secaudit_suppression_stale",
                lbl(kind=e["kind"], host=e["host"], key=e["match"]), 1)
    for e in invalid_sup:
        add("secaudit_suppression_invalid",
            lbl(kind=e["kind"], host=e["host"], key=e["match"],
                reason=e["invalid_reason"]), 1)

    for f in errors:
        add("secaudit_exporter_state_error", lbl(file=f), 1)

    # ---- render, with a hard per-family series cap ---------------------------------------------
    # The cap is what stands between one degenerate scan (a misparsed port range, nuclei with
    # `info` enabled) and hundreds of thousands of series in a 60d TSDB on a 14GB disk. Hitting it
    # is reported rather than silent, and the reporting family is rendered last so it can carry the
    # verdict for every family above it — including itself, which is never capped.
    out = []
    truncated = []
    for name, typ, help_ in _SECURITY_FAMILIES:
        if name == "secaudit_findings_truncated":
            continue
        rows = samples[name]
        if len(rows) > _SEC_MAX_SERIES:
            truncated.append(name)
            rows = rows[:_SEC_MAX_SERIES]
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {typ}")
        for labels, val in rows:
            out.append(f"{name}{{{labels}}} {val}" if labels else f"{name} {val}")
    out.append("# HELP secaudit_findings_truncated 1 if a family hit the series cap and was truncated")
    out.append("# TYPE secaudit_findings_truncated gauge")
    for name in truncated:
        out.append(f'secaudit_findings_truncated{{family="{name}"}} 1')
    return "\n".join(out) + "\n"


def entry_dir(uuid: str):
    """Return the containment-checked entry dir for a validated uuid, or None."""
    if not UUID_RE.match(uuid):
        return None
    d = os.path.realpath(os.path.join(STORE_DIR, uuid))
    if d != os.path.join(STORE_DIR, uuid) or not d.startswith(STORE_DIR + os.sep):
        return None  # traversal / escaped the store root
    return d


def load_active_script(uuid: str):
    """Return script bytes if the entry exists, is active and unexpired; else None."""
    d = entry_dir(uuid)
    if not d or not os.path.isdir(d):
        return None
    try:
        with open(os.path.join(d, "meta.json"), "r", encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("status") != "active":
            return None
        if time.time() > float(meta.get("expires_at", 0)):
            return None
        with open(os.path.join(d, "install.sh"), "rb") as f:
            return f.read()
    except (OSError, ValueError):
        return None


def burn(uuid: str) -> bool:
    d = entry_dir(uuid)
    if d and os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)
    return d is not None  # True if uuid was well-formed (idempotent even if already gone)


def reaper():
    while True:
        time.sleep(REAPER_INTERVAL)
        try:
            for name in os.listdir(STORE_DIR):
                d = os.path.join(STORE_DIR, name)
                meta_path = os.path.join(d, "meta.json")
                if not os.path.isfile(meta_path):
                    continue
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if time.time() > float(meta.get("expires_at", 0)):
                        shutil.rmtree(d, ignore_errors=True)
                except (OSError, ValueError):
                    continue
        except OSError:
            continue


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "provisioning/1"

    def _404(self):
        body = b"not found\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Per-container metrics exporter (internal only; VM scrapes it). Reuses Komodo stats.
        if self.path == "/metrics/containers":
            body = container_metrics_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        # Security auditor exporter (internal only). Renders security/state + policy from disk;
        # unlike /metrics/containers it makes no API call, so it stays fast and cannot hang.
        if self.path == "/metrics/security":
            body = security_metrics_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        # Prometheus http_sd (internal only — Traefik never routes /sd publicly).
        if self.path in SD_PORTS:
            body = json.dumps(sd_targets(SD_PORTS[self.path])).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        m = GET_RE.match(self.path)
        if not m:
            return self._404()
        body = load_active_script(m.group(1))
        if body is None:
            return self._404()
        self.send_response(200)
        self.send_header("Content-Type", "text/x-shellscript")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}") if n else {}
        except (ValueError, OSError):
            return {}

    def do_POST(self):
        # Komodo Custom alerter -> Alertmanager relay (internal only).
        if ALERT_RE.match(self.path):
            payload = self._json_body()
            ok, detail = post_alertmanager(komodo_alert_to_am(payload))
            if not ok:
                self.log_error("alert relay failed: %s", detail)
            self.send_response(200 if ok else 502)
            self.end_headers()
            return

        mb = BURN_RE.match(self.path)
        if mb:
            if not burn(mb.group(1)):
                return self._404()
            self.send_response(204)
            self.end_headers()
            return

        mc = COMPLETE_RE.match(self.path)
        if mc:
            uuid = mc.group(1)
            # Must be an active, unexpired entry (reuse the same gate as serving).
            if load_active_script(uuid) is None:
                return self._404()
            data = self._json_body()
            hostname = str(data.get("hostname", "")).strip()
            mesh_ip = str(data.get("mesh_ip", "")).strip()
            if not hostname or not MESH_IP_RE.match(mesh_ip):
                self.send_response(400)
                self.end_headers()
                return
            name = (NAME_BAD.sub("-", hostname).strip("-") or "host")[:64]
            role = entry_role(uuid)
            server_id, detail = komodo_register_server(name, mesh_ip)
            if not server_id:
                # Keep the link (TTL) so the operator can retry / add manually.
                self.log_error("CreateServer failed: %s", detail)
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"registration failed\n")
                return
            msg = "registered server"
            if role == APP_DEPLOY_ROLE:  # also create the per-host deploy Repo (+ tag)
                # Before the Repo: its seeded environment references [[<HOST>_JWT_SECRET]] and
                # [[<HOST>_DB_PASSWORD]], so the Variables have to exist or the first deploy writes
                # the placeholders through and the on_pull guard aborts it.
                jok, jdetail = komodo_ensure_host_secrets(name)
                if not jok:
                    self.log_error("per-host secret Variables failed: %s", jdetail)
                ok, rdetail = komodo_register_repo(server_id, name, mesh_ip)
                msg += " + repo" if ok else f" (repo skipped: {rdetail})"
                if ok and not jok:
                    msg += " (host secrets NOT created — set them before deploying)"
                if not ok:
                    self.log_error("CreateRepo failed: %s", rdetail)
            burn(uuid)  # server registered — remove the link
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write((msg + "\n").encode())
            return

        self._404()

    def log_message(self, fmt, *args):
        # Redact the uuid segment so the secret capability never lands in logs.
        redacted = re.sub(
            r"/provisioning/[^/]+/", "/provisioning/<uuid>/", self.path or ""
        )
        print(
            '%s - "%s %s" %s'
            % (self.client_address[0], self.command, redacted, args[1] if len(args) > 1 else "-"),
            flush=True,
        )


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    os.makedirs(STORE_DIR, exist_ok=True)
    threading.Thread(target=reaper, daemon=True).start()
    srv = Server(("0.0.0.0", LISTEN_PORT), Handler)
    print(f"provisioning listening on :{LISTEN_PORT}, store={STORE_DIR}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
