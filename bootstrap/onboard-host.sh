#!/usr/bin/env bash
# Onboard an application host to the manager-komodo control plane (Phase 1: management only).
#
# Everything is installed NATIVELY on the host (like Tailscale): no Periphery container.
#   - Tailscale client  -> systemd (tailscaled), joins the Headscale mesh.
#   - Komodo Periphery  -> systemd service (root), installed via Komodo's setup-periphery.py.
# This is additive and does NOT touch the running application. Periphery still uses the host's
# Docker to manage the app; running it natively (root) keeps it independent of the app's Docker
# lifecycle and lets Komodo also do OS-level ops (apt/reboot/cleanup) later.
#
# Idempotent: safe to re-run (updates versions, leaves existing config/keys intact).
#
# Target OS: Ubuntu/Debian minimal (apt). Run as root (sudo).
#
# Usage:
#   sudo ./onboard-host.sh --auth-key <hskey-...> --hostname <name> [--role gims-app] [--check]
#
#   --check   Run PREFLIGHT only and report feasibility. Makes no changes.
#
# May also be driven by env vars (used by the web-delivered flow, add-host.sh): KOMODO_AUTH_KEY,
# KOMODO_ROLE, KOMODO_LOGIN_SERVER, KOMODO_CORE_PUBKEY, KOMODO_HOSTNAME_DEFAULT, KOMODO_BURN_URL.

# Require bash (uses pipefail + ANSI-C quoting; dash would break). Must precede `set -o pipefail`.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "This installer requires bash. Re-run:  bash -c \"\$(curl -fsSL <url>)\"" >&2
  exit 1
fi

set -euo pipefail

# ---- Defaults (this control plane) ----
LOGIN_SERVER="${LOGIN_SERVER:-${KOMODO_LOGIN_SERVER:-https://komodo.segcore.eu}}"
CORE_PUBLIC_KEY="${CORE_PUBLIC_KEY:-${KOMODO_CORE_PUBKEY:-MCowBQYDK2VuAyEAq4h7qO1p9pLMSxUgADHXY8IYtUnhcTwpLUyiNiuT2y8=}}"
PERIPHERY_VERSION="${PERIPHERY_VERSION:-v2.2.0}"
SETUP_URL="${SETUP_URL:-https://raw.githubusercontent.com/moghtech/komodo/${PERIPHERY_VERSION}/scripts/setup-periphery.py}"
KOMODO_ROOT="${KOMODO_ROOT:-/etc/komodo}"
MANAGER_MESH_IP="${MANAGER_MESH_IP:-100.64.0.1}"
HEADSCALE_V4_RANGE="100.64.0.0/16"          # our mesh range (must not clash with other overlays)

AUTH_KEY=""; HOSTNAME_ARG=""; ROLE=""; CHECK_ONLY=0

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'
info() { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_yel}[!]${c_rst} $*"; }
err()  { echo "${c_red}[x]${c_rst} $*" >&2; }
die()  { err "$*"; exit 1; }
usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --auth-key)       AUTH_KEY="$2"; shift 2 ;;
    --hostname)       HOSTNAME_ARG="$2"; shift 2 ;;
    --role)           ROLE="$2"; shift 2 ;;
    --check)          CHECK_ONLY=1; shift ;;
    --login-server)   LOGIN_SERVER="$2"; shift 2 ;;
    --core-pubkey)    CORE_PUBLIC_KEY="$2"; shift 2 ;;
    --periphery-version) PERIPHERY_VERSION="$2"; shift 2 ;;
    -h|--help)        usage ;;
    *) die "unknown argument: $1 (use --help)" ;;
  esac
done

# Env-var fallbacks (explicit flags win). Lets the web-delivered preamble drive it with no args.
AUTH_KEY="${AUTH_KEY:-${KOMODO_AUTH_KEY:-}}"
ROLE="${ROLE:-${KOMODO_ROLE:-gims-app}}"
TAG="tag:${ROLE}"

# Interactive hostname prompt (default $(hostname)) when not provided and we have a terminal.
if [ -z "$HOSTNAME_ARG" ] && [ "$CHECK_ONLY" = 0 ] && [ -t 0 ]; then
  _def="${KOMODO_HOSTNAME_DEFAULT:-$(hostname)}"
  read -r -p "Hostname for this node [${_def}]: " _ans || true
  HOSTNAME_ARG="${_ans:-$_def}"
fi

# =====================================================================================
# PREFLIGHT — read-only. Abort before any change if blockers are found.
# =====================================================================================
BLOCKERS=0
block() { err "BLOCKER: $*"; BLOCKERS=$((BLOCKERS+1)); }
info "Preflight checks (no changes made yet)..."

[ "$(id -u)" = 0 ] || block "must run as root (use sudo)."

if [ -r /etc/os-release ]; then . /etc/os-release; else block "cannot read /etc/os-release"; fi
case "${ID:-}${ID_LIKE:-}" in
  *ubuntu*|*debian*) info "OS: ${PRETTY_NAME:-unknown} (apt-based) — OK" ;;
  *) block "unsupported OS '${PRETTY_NAME:-?}': targets Ubuntu/Debian (apt)." ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64|aarch64|arm64) info "Arch: $ARCH — OK" ;;
  *) block "unsupported architecture '$ARCH' (need x86_64 or arm64)." ;;
esac

if [ "$CHECK_ONLY" = 0 ]; then
  [ -n "$AUTH_KEY" ]     || block "--auth-key is required."
  [ -n "$HOSTNAME_ARG" ] || block "--hostname is required."
fi

if command -v curl >/dev/null 2>&1; then
  if curl -fsS -m 10 -o /dev/null "${LOGIN_SERVER}/health" 2>/dev/null \
     || curl -fsS -m 10 -o /dev/null "${LOGIN_SERVER}/" 2>/dev/null; then
    info "Egress to control plane (${LOGIN_SERVER}) — OK"
  else
    block "cannot reach control plane at ${LOGIN_SERVER} (check DNS/firewall egress)."
  fi
else
  warn "curl not present yet — will install; skipping egress check for now."
fi

# CGNAT route conflict (Netbird↔Tailscale). Only trips on a real overlap with our /16.
CONFLICT="$(ip -o route show 2>/dev/null | awk '$1 ~ /^100\.64\./ && $0 !~ /tailscale0/ {print}')"
if [ -n "$CONFLICT" ]; then
  block "existing route(s) overlap our mesh range ${HEADSCALE_V4_RANGE} via another interface:"
  echo "$CONFLICT" | sed 's/^/        /' >&2
fi
OTHER_OVERLAY="$(ip -o link show 2>/dev/null | grep -oE '(wt0|nb-[a-z0-9]+|netbird[0-9]*|wg[0-9]+)' | head -1 || true)"
[ -n "$OTHER_OVERLAY" ] && warn "overlay '$OTHER_OVERLAY' present; post-join check will confirm it survives."

command -v docker  >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
  && info "Docker + compose present — OK" || info "Docker/compose missing — will install."
command -v python3 >/dev/null 2>&1 && info "python3 present — OK" || info "python3 missing — will install (needed by setup-periphery.py)."

echo
[ "$BLOCKERS" -gt 0 ] && die "$BLOCKERS blocker(s) found. Nothing was changed. Fix the above and re-run."
info "Preflight PASSED — host can be onboarded."
if [ "$CHECK_ONLY" = 1 ]; then
  info "--check mode: no changes made. Re-run without --check to onboard."
  exit 0
fi

# =====================================================================================
# INSTALL / CONFIGURE — idempotent.
# =====================================================================================
info "Installing prerequisites (curl, ca-certificates, python3)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates python3 >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  info "Installing Docker (official convenience script, latest stable)..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

if ! command -v tailscale >/dev/null 2>&1; then
  info "Installing Tailscale..."
  curl -fsSL https://tailscale.com/install.sh | sh
fi
systemctl enable --now tailscaled >/dev/null 2>&1 || true

# Baseline of the other overlay (to detect breakage after join)
OVERLAY_OK_BEFORE=""
if [ -n "$OTHER_OVERLAY" ] && command -v netbird >/dev/null 2>&1; then
  netbird status 2>/dev/null | grep -qiE 'Connected' && OVERLAY_OK_BEFORE=1
fi

# Join the mesh (idempotent: an IP in our range means already joined)
if tailscale ip -4 2>/dev/null | grep -q '^100\.64\.'; then
  info "Already on the mesh (IP $(tailscale ip -4 | head -1)); skipping join (re-run)."
else
  info "Joining mesh as '${HOSTNAME_ARG}' with ${TAG} (tag forced on the key; no --advertise-tags)..."
  tailscale up --login-server "$LOGIN_SERVER" --auth-key "$AUTH_KEY" --hostname "$HOSTNAME_ARG"
fi

TS_IP="$(tailscale ip -4 2>/dev/null | head -1 || true)"
[ -n "$TS_IP" ] || die "no Tailscale IPv4 assigned — join failed."
case "$TS_IP" in 100.64.*) : ;; *) warn "mesh IP $TS_IP is outside ${HEADSCALE_V4_RANGE} (unexpected)";; esac
info "Mesh IP: $TS_IP"

ping -c2 -W3 "$MANAGER_MESH_IP" >/dev/null 2>&1 \
  && info "Manager ($MANAGER_MESH_IP) reachable over the mesh — OK" \
  || warn "cannot ping manager ($MANAGER_MESH_IP) yet — mesh may still be settling."

if [ -n "$OVERLAY_OK_BEFORE" ]; then
  if netbird status 2>/dev/null | grep -qiE 'Connected'; then
    info "Other overlay ($OTHER_OVERLAY) still connected — coexistence OK."
  else
    err "overlay ($OTHER_OVERLAY) went DOWN after join. Rolling back (tailscale down)."
    tailscale down || true
    die "rolled back to protect existing connectivity. Investigate routes before retrying."
  fi
fi

# --- Native Periphery config (written BEFORE setup so it uses ours). ---
# Accept connections only from our Core (its public key) and only from the mesh range.
# bind_ip stays default [::] on port 8120 -> no boot-ordering dependency on the mesh IP;
# access is restricted by allowed_ips + the Core key + the host firewall.
info "Writing Periphery config (${KOMODO_ROOT}/periphery.config.toml)..."
mkdir -p "$KOMODO_ROOT"
cat > "${KOMODO_ROOT}/periphery.config.toml" <<TOML
# Komodo Periphery — managed by onboard-host.sh
root_directory = "${KOMODO_ROOT}"
core_public_keys = ["${CORE_PUBLIC_KEY}"]
allowed_ips = ["${HEADSCALE_V4_RANGE}"]
TOML

# --- Install/refresh the native systemd Periphery via Komodo's setup script ---
info "Installing native Periphery ${PERIPHERY_VERSION} (systemd, root)..."
TMP_SETUP="$(mktemp --suffix=.py)"
curl -fsSL "$SETUP_URL" -o "$TMP_SETUP"
python3 "$TMP_SETUP" --version "$PERIPHERY_VERSION" --connect-as "$HOSTNAME_ARG"
rm -f "$TMP_SETUP"

systemctl daemon-reload
systemctl enable periphery >/dev/null 2>&1 || true
systemctl restart periphery
sleep 3

# --- Verify ---
if systemctl is-active --quiet periphery; then
  info "periphery.service active — OK"
else
  err "periphery.service not active. Check: journalctl -u periphery -n50"; exit 1
fi
if ss -Htln 2>/dev/null | grep -q ':8120'; then
  info "Periphery listening on :8120 — OK"
else
  warn "port 8120 not detected; check 'journalctl -u periphery -n50'."
fi

# --- Tell the control plane we're done: it auto-registers this host in Komodo (Core -> periphery)
#     and burns the provisioning link. Best-effort; the link also expires via its TTL. ---
if [ -n "${KOMODO_COMPLETE_URL:-}" ]; then
  info "Registering with the control plane..."
  if curl -fsS -m 15 -X POST -H 'Content-Type: application/json' \
       -d "{\"hostname\":\"${HOSTNAME_ARG}\",\"mesh_ip\":\"${TS_IP}\"}" \
       "$KOMODO_COMPLETE_URL" >/dev/null 2>&1; then
    info "Registered in Komodo Core as a Server; provisioning link burned."
  else
    warn "auto-registration failed; add the server manually in Komodo"
    warn "  (Servers -> New Server -> https://${TS_IP}:8120). The link expires via TTL."
  fi
fi

echo
info "DONE. Host '${HOSTNAME_ARG}' is on the mesh with native Periphery running (root, systemd)."
info "Next: in Komodo Core (https://komodo.apps.internal) -> Servers -> New Server -> address:"
info "      https://${TS_IP}:8120   (periphery serves TLS self-signed; Core uses wss)"
