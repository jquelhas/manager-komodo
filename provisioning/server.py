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
import http.server
import json
import os
import re
import shutil
import socketserver
import threading
import time
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
_TAG_ID = {}


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


def komodo_register_repo(server_id, name):
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


_CONTAINER_FAMILIES = [
    ("komodo_container_running", "gauge", "1 if the container state is running"),
    ("komodo_container_cpu_percent", "gauge", "CPU usage percent (docker stats via Komodo Periphery)"),
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
            lbl = f'host="{_lbl(host)}",name="{_lbl(name)}"'
            samples["komodo_container_running"].append((lbl, 1 if c.get("state") == "running" else 0))
            st = c.get("stats") or {}
            if not isinstance(st, dict):
                continue

            def add(metric, val):
                if val is not None:
                    samples[metric].append((lbl, val))

            add("komodo_container_cpu_percent", _pct(st.get("cpu_perc")))
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
                ok, rdetail = komodo_register_repo(server_id, name)
                msg += " + repo" if ok else f" (repo skipped: {rdetail})"
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
