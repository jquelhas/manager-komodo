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

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
GET_RE = re.compile(r"^/provisioning/([^/]+)/install\.sh$")
BURN_RE = re.compile(r"^/provisioning/([^/]+)/burn$")
COMPLETE_RE = re.compile(r"^/provisioning/([^/]+)/complete$")
# mesh_ip is used to build the Server address Core will dial — only accept our mesh range.
MESH_IP_RE = re.compile(r"^100\.64\.\d{1,3}\.\d{1,3}$")
NAME_BAD = re.compile(r"[^A-Za-z0-9._-]")


def komodo_create_server(name, mesh_ip):
    """Register the host as a Komodo Server (idempotent-ish). Returns (ok, detail)."""
    if not (KOMODO_API_KEY and KOMODO_API_SECRET):
        return False, "no Komodo API credentials configured"
    body = json.dumps(
        {"name": name, "config": {"address": f"https://{mesh_ip}:8120", "enabled": True}}
    ).encode()
    req = urllib.request.Request(
        f"{KOMODO_CORE_URL}/write/CreateServer",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": KOMODO_API_KEY,
            "X-Api-Secret": KOMODO_API_SECRET,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return (200 <= r.status < 300), f"http {r.status}"
    except urllib.error.HTTPError as e:
        detail = (e.read() or b"").decode(errors="replace").lower()
        # A name clash means it is already registered — treat as success (idempotent).
        if any(w in detail for w in ("exist", "duplicate", "taken", "unique")):
            return True, "already registered"
        return False, f"http {e.code}: {detail[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


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
            ok, detail = komodo_create_server(name, mesh_ip)
            if ok:
                burn(uuid)  # done: register succeeded, remove the link
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"registered\n")
            else:
                # Keep the link (TTL) so the operator can retry / add manually.
                self.log_error("CreateServer failed: %s", detail)
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"registration failed\n")
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
