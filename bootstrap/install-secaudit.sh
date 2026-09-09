#!/usr/bin/env bash
# Install (or update, or remove) the secaudit host bundle. Runs ON the machine being audited,
# as root. Idempotent: re-run it after editing secaudit/versions.env to update the scanners.
#
# The manager deliberately has NO SSH access to the app hosts, so this is carried there by an
# operator rather than pushed. Giving the manager root SSH to the whole fleet would be a wider
# privilege path than anything this auditor is trying to protect. Build the bundle with
# `scripts/secaudit.sh bundle` on the manager; it prints the exact commands.
#
# Usage (as root, from the unpacked bundle directory):
#   ./install-secaudit.sh [--dry-run] [--perimeter-targets "name=ip name=ip"] [--no-enable]
#   ./install-secaudit.sh --uninstall
#
# What it installs:
#   /opt/secaudit/{lynis,docker-bench,run.py,versions.env}
#   /etc/systemd/system/secaudit-host.{service,timer,path}
#   /var/lib/secaudit  (report.ndjson + trigger.d)   /var/log/secaudit
#
# What it does NOT do: it never runs apt-get update/upgrade, never touches sshd or any other
# service, and never starts an audit by itself. After installing, run one audit by hand and watch
# it before relying on the timer.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="$SRC_DIR/secaudit"
PREFIX="${SECAUDIT_ROOT:-/opt/secaudit}"
STATE="${SECAUDIT_STATE:-/var/lib/secaudit}"
CACHE="${SECAUDIT_CACHE:-/var/cache/secaudit}"
LOGDIR="${SECAUDIT_LOG:-/var/log/secaudit}"
UNIT_DIR="${SECAUDIT_UNIT_DIR:-/etc/systemd/system}"

c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
info() { echo "${c_grn}[+]${c_rst} $*"; }
warn() { echo "${c_yel}[!]${c_rst} $*" >&2; }
die()  { echo "${c_red}[x]${c_rst} $*" >&2; exit 1; }

DRY=0; UNINSTALL=0; NO_ENABLE=0; PERIMETER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)            DRY=1; shift ;;
    --uninstall)          UNINSTALL=1; shift ;;
    --no-enable)          NO_ENABLE=1; shift ;;
    --perimeter-targets)  PERIMETER="${2:-}"; shift 2 ;;
    -h|--help)            sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                    die "unknown argument: $1" ;;
  esac
done

run() { if [ "$DRY" = 1 ]; then echo "    would: $*"; else "$@"; fi; }

[ "$(id -u)" = 0 ] || die "must run as root (use sudo)"

# ---------------------------------------------------------------------------------------------
# Uninstall: complete by construction, because nothing outside these paths was ever touched.
# ---------------------------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  info "removing the secaudit bundle"
  for u in secaudit-host.timer secaudit-host.path; do
    systemctl is-enabled --quiet "$u" 2>/dev/null && run systemctl disable --now "$u" || true
  done
  run rm -f "$UNIT_DIR"/secaudit-host.{service,timer,path}
  run systemctl daemon-reload
  # $CACHE is still removed even though nothing creates it any more: installs from before
  # 2026-09-08 left a ~1.3 GB trivy database behind, and uninstall must be complete.
  run rm -rf "$PREFIX" "$STATE" "$CACHE" "$LOGDIR"
  info "removed. Nothing else on this host was ever modified."
  exit 0
fi

# ---------------------------------------------------------------------------------------------
# Preflight. Fail before changing anything, the same posture as bootstrap/onboard-host.sh.
# ---------------------------------------------------------------------------------------------
[ -d "$BUNDLE" ] || die "bundle directory not found: $BUNDLE (unpack the whole tarball)"
[ -f "$BUNDLE/versions.env" ] || die "missing $BUNDLE/versions.env"
[ -f "$BUNDLE/run.py" ] || die "missing $BUNDLE/run.py"

. /etc/os-release 2>/dev/null || true
case "${ID:-}${ID_LIKE:-}" in
  *ubuntu*|*debian*) info "OS: ${PRETTY_NAME:-unknown} — OK" ;;
  *) die "unsupported OS '${PRETTY_NAME:-?}': this bundle targets Ubuntu/Debian" ;;
esac
for bin in curl tar sha256sum python3 systemctl ss; do
  command -v "$bin" >/dev/null || die "missing required command: $bin"
done
command -v docker >/dev/null || warn "docker not found — the docker-bench step will report tool_error"

# shellcheck disable=SC1090
. "$BUNDLE/versions.env"
: "${SECAUDIT_LYNIS_URL:?}" "${SECAUDIT_LYNIS_SHA256:?}" "${SECAUDIT_LYNIS_VERSION:?}"
: "${SECAUDIT_BENCH_URL:?}" "${SECAUDIT_BENCH_SHA256:?}" "${SECAUDIT_BENCH_VERSION:?}"

# The unit is rewritten from scratch on every run, so an option not repeated would be silently
# dropped. For the perimeter targets that would quietly disable the cross-scan — the only check
# that verifies the external firewall allowlist and the Headscale ACL — while everything still
# looked healthy. So: carry the existing value forward unless a new one is given, and say so.
if [ -z "$PERIMETER" ] && [ -f "$UNIT_DIR/secaudit-host.service" ]; then
  PERIMETER="$(sed -n 's/^Environment="SECAUDIT_PERIMETER_TARGETS=\(.*\)"$/\1/p' \
                 "$UNIT_DIR/secaudit-host.service" | head -n1)"
  # tolerate the pre-2026-09-06 unquoted form, which systemd split and truncated
  [ -n "$PERIMETER" ] || PERIMETER="$(sed -n 's/^Environment=SECAUDIT_PERIMETER_TARGETS=\(.*\)$/\1/p' \
                 "$UNIT_DIR/secaudit-host.service" | head -n1)"
  [ -z "$PERIMETER" ] || info "keeping the existing perimeter targets: $PERIMETER"
fi

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT

# fetch <url> <sha256> <dest>. A hash mismatch ABORTS — it is never a warning. These artifacts are
# about to run as root on a production machine.
fetch() {
  local url="$1" want="$2" dest="$3" got
  info "  fetching $(basename "$url")"
  if [ "$DRY" = 1 ]; then echo "    would: curl -fsSL $url  (verify $want)"; return 0; fi
  curl -fsSL --retry 3 --max-time 300 -o "$dest" "$url" || die "download failed: $url"
  got="$(sha256sum "$dest" | cut -d' ' -f1)"
  [ "$got" = "$want" ] || die "SHA-256 MISMATCH for $url
    expected: $want
    got:      $got
  Refusing to install. Either versions.env is stale or the artifact changed upstream."
  info "    sha256 ok"
}

# Skip work that is already done: the marker records exactly which pinned set is installed.
MARKER="$PREFIX/.installed"
WANT_MARK="lynis=$SECAUDIT_LYNIS_SHA256 bench=$SECAUDIT_BENCH_SHA256"
HAVE_MARK="$(cat "$MARKER" 2>/dev/null || true)"

info "installing secaudit bundle into $PREFIX"
# $PREFIX belongs in this list even though the payload is unpacked into it further down: the
# chmod right below it runs unconditionally, and on a host where /opt/secaudit does not exist yet
# the whole installer died on "chmod: cannot access". It went unnoticed on the manager and on
# segcore-demo because the directory was already there from an earlier install — a fresh host was
# the only place it could show, and segcore-host1 was the first one (2026-09-09).
run mkdir -p "$PREFIX" "$STATE/trigger.d" "$LOGDIR"
# 0751 on the prefix: traversable but not listable. `run.py --summary` is a read-only view of a
# world-readable report, so needing sudo just to reach the script was a wart — but nobody should be
# able to enumerate what is installed here either. The cache and the log dir stay 0750: lynis
# writes a detailed inventory of the machine into its log, which is genuinely sensitive.
run chmod 0751 "$PREFIX"
run chmod 0750 "$LOGDIR"
run chmod 0755 "$STATE"          # the collect courier bind-mounts this read-only
run chmod 0733 "$STATE/trigger.d"  # write-only for the trigger courier: it drops a sentinel, it
                                   # can never read or replace report.ndjson

if [ "$HAVE_MARK" = "$WANT_MARK" ] && [ "$DRY" = 0 ]; then
  info "  scanners already at the pinned versions — skipping downloads"
else
  WORK="$(mktemp -d)"
  fetch "$SECAUDIT_LYNIS_URL" "$SECAUDIT_LYNIS_SHA256" "$WORK/lynis.tgz"
  fetch "$SECAUDIT_BENCH_URL" "$SECAUDIT_BENCH_SHA256" "$WORK/bench.tgz"

  info "  unpacking (replacing any previous copy)"
  if [ "$DRY" = 0 ]; then
    rm -rf "$PREFIX/lynis" "$PREFIX/docker-bench"
    mkdir -p "$PREFIX/lynis" "$PREFIX/docker-bench"
    # --strip-components=1: both archives have a single top-level directory whose name carries the
    # version, so stripping it keeps the install path stable across upgrades.
    tar xzf "$WORK/lynis.tgz" -C "$PREFIX/lynis" --strip-components=1
    tar xzf "$WORK/bench.tgz" -C "$PREFIX/docker-bench" --strip-components=1
    chmod 0755 "$PREFIX/lynis/lynis" "$PREFIX/docker-bench/docker-bench-security.sh"
    echo "$WANT_MARK" > "$MARKER"; chmod 0600 "$MARKER"
  else
    echo "    would: unpack lynis and docker-bench into $PREFIX"
  fi
fi

# Remove what a previous layout left behind. Image CVE scanning moved to the application's CI on
# 2026-09-08 and nothing here uses trivy any more, but an install from before that date leaves a
# ~1.3 GB vulnerability database and the binary sitting on the host forever. An update that does
# not clean up after itself is how disks fill quietly.
for stale in "$PREFIX/bin/trivy" "$CACHE"; do
  if [ -e "$stale" ]; then
    info "  removing obsolete $stale ($(du -sh "$stale" 2>/dev/null | cut -f1))"
    run rm -rf "$stale"
  fi
done
rmdir "$PREFIX/bin" 2>/dev/null || true

info "  installing run.py and versions.env"
run install -m 0755 "$BUNDLE/run.py" "$PREFIX/run.py"
run install -m 0644 "$BUNDLE/versions.env" "$PREFIX/versions.env"

# ---------------------------------------------------------------------------------------------
# systemd units. The hardening block is the real containment guarantee: with ProtectSystem=strict
# the audit cannot write to /etc or /usr even as root, even with a bug in run.py. The cgroup limits
# DO apply here (unlike the manager-side scans, which run via `docker run` and land in dockerd's
# cgroup) because these tools are direct children of the unit.
# ---------------------------------------------------------------------------------------------
info "  installing systemd units into $UNIT_DIR"
write_unit() {  # $1 = filename, stdin = content
  if [ "$DRY" = 1 ]; then echo "    would: write $UNIT_DIR/$1"; cat >/dev/null; return 0; fi
  mkdir -p "$UNIT_DIR"      # always there on a real host; not when UNIT_DIR is overridden to test
  cat > "$UNIT_DIR/$1"; chmod 0644 "$UNIT_DIR/$1"
}

write_unit secaudit-host.service <<UNIT
[Unit]
Description=secaudit host audit (listeners, lynis, docker-bench)
Documentation=https://github.com/jquelhas/manager-komodo/blob/main/docs/plan/secaudit.md
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
User=root
WorkingDirectory=$PREFIX
ExecStart=$PREFIX/run.py
# QUOTE every value. systemd's Environment= takes SPACE-SEPARATED assignments, so an unquoted
# value containing a space is silently split: "TARGETS=a=1 b=2" became TARGETS=a=1 plus a stray
# b=2, which dropped the mesh target and would have left the ACL check never running while
# everything still looked healthy. Verified with a throwaway unit on 2026-09-06.
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="SECAUDIT_ROOT=$PREFIX"
Environment="SECAUDIT_STATE=$STATE"
Environment="SECAUDIT_LOG=$LOGDIR"
Environment="SECAUDIT_PERIMETER_TARGETS=$PERIMETER"
# Containment enforced by the kernel, not promised by the script: everything is read-only except
# the three secaudit paths. /run/docker.sock is listed because connect() on a unix socket needs
# write access to the inode, which ProtectSystem=strict would otherwise deny.
ProtectSystem=strict
ReadWritePaths=$STATE $LOGDIR /run/docker.sock
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
RestrictSUIDSGID=yes
# Bound the auditor so that IT fails rather than anything else on the box: an OOM here shows up as
# a tool_error and a stale-scan alert, never as pressure on the application. The heaviest step
# (image CVE scanning) has moved to CI, so these limits now have a lot of headroom — keep them
# anyway, because the whole point is that the auditor can never be the thing that hurts the host.
MemoryMax=1G
MemoryHigh=768M
CPUQuota=100%
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=3600
UNIT

write_unit secaudit-host.timer <<UNIT
[Unit]
Description=Daily secaudit host audit

[Timer]
OnCalendar=*-*-* 01:00:00 UTC
# Spread the fleet: three machines auditing at the same second is pointless load, and the
# manager's collection runs at 01:45 which leaves room for the jitter.
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
UNIT

write_unit secaudit-host.path <<UNIT
[Unit]
Description=Run the secaudit host audit on demand
Documentation=man:systemd.path(5)

[Path]
# The manager requests an out-of-band audit by dropping this sentinel through a zero-privilege
# courier container (see scripts/setup-secaudit.sh). run.py deletes it first thing, so it cannot
# loop. The worst an abuse of this path achieves is asking for an audit.
PathExists=$STATE/trigger.d/run
Unit=secaudit-host.service

[Install]
WantedBy=paths.target
UNIT

run systemctl daemon-reload
if [ "$NO_ENABLE" = 1 ]; then
  warn "units installed but NOT enabled (--no-enable). Enable with:"
  warn "  systemctl enable --now secaudit-host.timer secaudit-host.path"
else
  run systemctl enable --now secaudit-host.timer secaudit-host.path
fi

if [ "$DRY" = 1 ]; then
  info "dry run complete — nothing was changed."
  exit 0
fi

cat <<EOM

${c_grn}Installed.${c_rst} Versions: lynis $SECAUDIT_LYNIS_VERSION, docker-bench $SECAUDIT_BENCH_VERSION

Next, run ONE audit by hand and watch it before trusting the timer (it takes 5-10 minutes; lynis
alone is around 2). ALWAYS through systemd, never ./run.py directly — the unit carries the memory
cap and the filesystem containment, and a bare run has neither:

  systemctl start secaudit-host.service && journalctl -u secaudit-host.service -f

Then check the report and the step results:

  $PREFIX/run.py --summary        # read-only digest; no sudo needed
  sudo grep '"k":"tool_error"' $STATE/report.ndjson || echo "no tool errors"

The manager collects it from here; nothing on this host listens on a port for it.
To remove everything: $0 --uninstall
EOM
