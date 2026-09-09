#!/usr/bin/env bash
# Fast security sensor: runs every 5 minutes, touches no host, costs nothing.
#
# Three independent signals, each with its own freshness bookkeeping so one failing does not mask
# the others:
#   listeners     what is BOUND on the manager itself (ss). Process attribution is empty for
#                 root-owned sockets because this runs as `ubuntu` — by design; see docs/plan.
#   docker_ports  every PUBLISHED container port across the fleet, with its bind IP, straight from
#                 Komodo's read/ListDockerContainers. This is the cheap half of exposure drift: a
#                 stray `-p 5432:5432` on any host shows up here within 5 minutes, with no agent
#                 and no scan. Non-Docker listeners on the app hosts need the native bundle
#                 (phase 2) — this view is deliberately partial and records `source` to say so.
#   drift         the internal-service checklist: a Traefik router whose name is missing from
#                 Headscale DNS or from step-ca's extra_hosts, and — the direction that actually
#                 caused the 2026-08-23 outage — a step-ca extra_hosts entry with NO router, which
#                 can never complete TLS-ALPN and stalls the WHOLE internal renewal queue.
#
# This script only collects facts. Classifying a bind address as public/mesh/loopback, comparing
# against the baseline and applying suppressions all happen in the exporter at scrape time, so a
# baseline edit takes effect in ~60s without re-running anything.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/security-lib.sh"
cd "$SEC_REPO_DIR"
sec_load_env

case "${SECAUDIT_ENABLED,,}" in
  1|true|yes) ;;
  *) sec_scan_skip listeners disabled; sec_scan_skip docker_ports disabled; exit 0 ;;
esac
# komodo-core is stopped during the backup window: the fleet half would fail for a benign reason.
sec_require_no_backup listeners || exit 0

# ---- 1. local listeners on the manager --------------------------------------------------------
sec_scan_begin listeners manager
if ss -lntupH > /tmp/secaudit-ss.$$ 2>/dev/null; then
  python3 - "/tmp/secaudit-ss.$$" > /tmp/secaudit-ss.json.$$ <<'PY'
import json, re, sys, time
out = []
for line in open(sys.argv[1]):
    f = line.split()
    if len(f) < 5:
        continue
    proto, state, local = f[0], f[1], f[4]
    if proto not in ("tcp", "udp"):
        continue
    if proto == "tcp" and state != "LISTEN":
        continue
    # local is addr:port, where addr may be [::1], 0.0.0.0, or 127.0.0.53%lo (interface-scoped)
    addr, _, port = local.rpartition(":")
    if not port.isdigit():
        continue
    addr = addr.split("%")[0]
    family = 6 if addr.startswith("[") else 4
    addr = addr.strip("[]")
    proc = ""
    m = re.search(r'users:\(\("([^"]+)"', line)
    if m:
        proc = m.group(1)
    out.append({"proto": proto, "family": family, "addr": addr,
                "port": int(port), "process": proc})
out.sort(key=lambda d: (d["proto"], d["port"], d["addr"]))
print(json.dumps({"schema": 1, "ts": int(time.time()), "host": "manager",
                  "source": "local_socket", "listeners": out}))
PY
  sec_state_write listeners.json < /tmp/secaudit-ss.json.$$
  sec_scan_end 1 "$(jq '.listeners | length' /tmp/secaudit-ss.json.$$)"
else
  sec_warn "ss failed"
  sec_scan_end 0 0
fi
rm -f /tmp/secaudit-ss.$$ /tmp/secaudit-ss.json.$$

# ---- 2. published container ports, manager + every Komodo server ------------------------------
sec_scan_begin docker_ports manager
hosts_json='{}'
ports_total=0
ok_all=1

# The manager, from the local daemon. Only entries containing "->" are PUBLISHED; a bare "9120/tcp"
# is merely EXPOSED (image metadata) and reaches nothing — counting those is a classic false
# positive.
mgr_ports="$(docker ps --format '{{.Names}}|{{.Ports}}' \
  | python3 -c '
import json, sys
out = []
for line in sys.stdin:
    name, _, ports = line.rstrip("\n").partition("|")
    for p in ports.split(", "):
        if "->" not in p:
            continue
        left, _, right = p.partition("->")
        addr, _, port = left.rpartition(":")
        proto = right.split("/")[-1] if "/" in right else "tcp"
        if not port.isdigit():
            continue
        out.append({"container": name, "proto": proto,
                    "addr": addr.strip("[]"), "port": int(port)})
print(json.dumps(out))')"
hosts_json="$(jq -c --argjson p "$mgr_ports" '. + {manager: {ok: true, source: "docker_cli", ports: $p}}' <<<"$hosts_json")"
ports_total=$(( ports_total + $(jq 'length' <<<"$mgr_ports") ))

while IFS=$'\t' read -r host scannable; do
  [ -n "$host" ] || continue
  if [ "$scannable" != "1" ]; then
    hosts_json="$(jq -c --arg h "$host" '. + {($h): {ok: false, source: "komodo_api", reason: "host not Ok", ports: []}}' <<<"$hosts_json")"
    continue
  fi
  conts="$(kapi read/ListDockerContainers "$(jq -nc --arg s "$host" '{server:$s}')" 2>/dev/null || true)"
  if ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"${conts:-null}"; then
    sec_warn "ListDockerContainers failed for $host"
    ok_all=0
    hosts_json="$(jq -c --arg h "$host" '. + {($h): {ok: false, source: "komodo_api", reason: "api error", ports: []}}' <<<"$hosts_json")"
    continue
  fi
  # PublicPort null => not published. IP "" with a PublicPort would mean a wildcard bind, which
  # Docker normally reports as 0.0.0.0; normalise it so the exporter never has to guess.
  hp="$(jq -c '[ .[] | .name as $n | .ports[]? | select(.PublicPort != null)
                | {container: $n, proto: (.Type // "tcp"),
                   addr: (if (.IP // "") == "" then "0.0.0.0" else .IP end),
                   port: .PublicPort} ]' <<<"$conts")"
  hosts_json="$(jq -c --arg h "$host" --argjson p "$hp" '. + {($h): {ok: true, source: "komodo_api", ports: $p}}' <<<"$hosts_json")"
  ports_total=$(( ports_total + $(jq 'length' <<<"$hp") ))
done < <(jq -r '.targets[] | select(.host != "manager") | [.host, (.scannable|tostring)] | @tsv' \
            "$(sec_state_path targets.json)" 2>/dev/null || true)

jq -n --argjson ts "$(date +%s)" --argjson h "$hosts_json" \
  '{schema:1, ts:$ts, hosts:$h}' | sec_state_write docker-ports.json
sec_scan_end "$ok_all" "$ports_total"

# ---- 4. image freshness across the fleet ------------------------------------------------------
# The counterpart to CI scanning, not a replacement for it. CI knows whether the image it just
# built was vulnerable; only the host knows what is actually running, and for how long. An image
# built months ago has stopped receiving base-layer patches — whether that is a deliberate pin or a
# deploy that quietly never happened, both are worth seeing.
#
# Komodo's read/ListImages already reports `created` and computes `in_use` itself, so this costs
# one API call per host and needs nothing installed anywhere.
sec_scan_begin images manager
imgs_json='{}'
img_total=0
img_ok=1

# The manager's own daemon, locally.
mgr_imgs="$(docker images --format '{{.Repository}}:{{.Tag}}|{{.CreatedAt}}' --filter dangling=false 2>/dev/null \
  | python3 -c '
import json, sys, time, datetime
running = set()
out = []
for line in sys.stdin:
    ref, _, created = line.rstrip("\n").partition("|")
    if not ref or ref.endswith(":<none>"):
        continue
    try:
        # docker prints "2026-09-07 18:51:22 +0000 UTC"
        ts = int(datetime.datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S")
                 .replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        continue
    out.append({"name": ref, "created": ts})
print(json.dumps(out))')"
mgr_running="$(docker ps --format '{{.Image}}' 2>/dev/null | python3 -c '
import json, sys
def norm(r):
    r = r.strip()
    if not r or "@" in r: return r
    return r if ":" in r.rsplit("/", 1)[-1] else r + ":latest"
print(json.dumps(sorted({norm(l) for l in sys.stdin if l.strip()})))')"
mgr="$(jq -nc --argjson i "${mgr_imgs:-[]}" --argjson r "${mgr_running:-[]}" \
  '{ok:true, images:[ $i[] | . + {in_use: (.name as $n | $r | index($n) != null)} ]}')"
imgs_json="$(jq -c --argjson m "$mgr" '. + {manager: $m}' <<<"$imgs_json")"
img_total=$(( img_total + $(jq '[.images[]|select(.in_use)]|length' <<<"$mgr") ))

while IFS=$'\t' read -r host scannable; do
  [ -n "$host" ] || continue
  [ "$scannable" = "1" ] || continue
  li="$(kapi read/ListImages "$(jq -nc --arg s "$host" '{server:$s}')" 2>/dev/null || true)"
  if ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"${li:-null}"; then
    sec_warn "ListImages failed for $host"
    img_ok=0
    imgs_json="$(jq -c --arg h "$host" '. + {($h): {ok:false, images:[]}}' <<<"$imgs_json")"
    continue
  fi
  hi="$(jq -c '[ .[] | select((.name // "") != "" and (.name | endswith(":<none>") | not))
                | {name, created, in_use: (.in_use // false)} ]' <<<"$li")"
  imgs_json="$(jq -c --arg h "$host" --argjson i "$hi" '. + {($h): {ok:true, images:$i}}' <<<"$imgs_json")"
  img_total=$(( img_total + $(jq '[.[]|select(.in_use)]|length' <<<"$hi") ))
done < <(jq -r '.targets[] | select(.host != "manager") | [.host, (.scannable|tostring)] | @tsv' \
            "$(sec_state_path targets.json)" 2>/dev/null || true)

jq -n --argjson ts "$(date +%s)" --argjson h "$imgs_json" '{schema:1, ts:$ts, hosts:$h}' \
  | sec_state_write images.json
sec_scan_end "$img_ok" "$img_total"

# ---- 5. Periphery agent version vs the Core ---------------------------------------------------
# Periphery is the ONLY channel the manager has to a host, and its version is expected to track the
# Core's. Nothing enforced that: on 2026-09-09 a freshly onboarded host came up on 2.2.0 against a
# Core on 2.3.2 (two pins for the same version, in add-host.sh and onboard-host.sh, and the stale
# one won). It was found by accident. This is what would have found it on the next scrape.
#
# The check is here rather than in the exporter because the exporter makes no API calls on purpose
# -- it renders state from disk so /metrics/security cannot hang. Two calls, whole fleet.
sec_scan_begin agents manager
agents_ok=1
core_ver="$(kapi read/GetVersion '{}' 2>/dev/null | jq -r '.version // ""')"
srv="$(kapi read/ListServers '{}' 2>/dev/null || true)"
if [ -z "$core_ver" ] || ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"${srv:-null}"; then
  sec_warn "GetVersion/ListServers failed — agent version skew not measured"
  sec_scan_end 0 0
else
  jq -n --argjson ts "$(date +%s)" --arg core "$core_ver" --argjson s "$srv" \
    '{schema:1, ts:$ts, core:$core,
      agents: ( [ $s[] | {key: .name,
                          value: {version: (.info.version // ""), state: (.info.state // "")}} ]
                | from_entries )}' \
    | sec_state_write agents.json
  sec_scan_end "$agents_ok" "$(jq 'length' <<<"$srv")"
fi

# ---- 6. internal-service checklist drift ------------------------------------------------------
# Homepage is deliberately NOT checked: a missing tile is cosmetic and never broke anything, while
# several legitimate names (step-ca, the tailscale alias, Homepage itself) have no href by design —
# checking it would produce four permanent false positives and train us to ignore the alert.
sec_scan_begin drift manager
docker ps -q | xargs -r docker inspect --format '{{json .Config.Labels}}' > /tmp/secaudit-lbl.$$ 2>/dev/null || true
python3 - "/tmp/secaudit-lbl.$$" > /tmp/secaudit-drift.json.$$ <<'PY'
import json, re, sys, time
names = set()
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        for k, v in (json.loads(line) or {}).items():
            if k.endswith(".rule"):
                names.update(re.findall(r"Host(?:SNI)?\(`([^`]+)`\)", v))
routers = {n for n in names if n == "apps.internal" or n.endswith(".apps.internal")}

with open("docker/headscale/config.yaml") as f:
    dns = set(re.findall(r'^\s*-\s*name:\s*"([^"]+)"', f.read(), re.M))
with open("docker-compose.yml") as f:
    hosts = set(re.findall(r'^\s*-\s*"([^":]+\.internal):', f.read(), re.M))

findings = []
for n in sorted(routers):
    missing = []
    if n not in dns:
        missing.append("dns")
    if n not in hosts:
        missing.append("stepca_hosts")
    for m in missing:
        findings.append({"name": n, "missing": m})
# The inverse, and the one that caused the 2026-08-23 outage: a step-ca extra_hosts entry with no
# router behind it can never answer TLS-ALPN-01, and one such entry stalls every internal renewal.
for n in sorted(hosts - routers):
    findings.append({"name": n, "missing": "router"})

print(json.dumps({"schema": 1, "ts": int(time.time()),
                  "routers": sorted(routers), "findings": findings}))
PY
if [ -s /tmp/secaudit-drift.json.$$ ]; then
  sec_state_write drift.json < /tmp/secaudit-drift.json.$$
  n="$(jq '.findings | length' /tmp/secaudit-drift.json.$$)"
  [ "$n" = "0" ] || sec_warn "internal-name drift: $n finding(s)"
  sec_scan_end 1 "$(jq '.routers | length' /tmp/secaudit-drift.json.$$)"
else
  sec_warn "drift check failed"
  sec_scan_end 0 0
fi
rm -f /tmp/secaudit-lbl.$$ /tmp/secaudit-drift.json.$$
