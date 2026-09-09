#!/usr/bin/env bash
# Upgrade Komodo Periphery on an app host so it matches the Core. ON DEMAND, never on a timer.
#
# Run on the MANAGER. It does NOT touch any host: the manager deliberately has no SSH to the fleet
# (root SSH from here to every host would be a wider privilege path than anything it protects), so
# this publishes the verified installer MESH-ONLY at https://apps.internal/artifacts/ and prints
# one command — the same for every host — to paste there. "Carry, not push", like the secaudit
# bundle.
#
# NOT over /provisioning/<uuid>/ and not over the public endpoint. That channel is the COLD START:
# it exists because a brand-new host is not on the mesh yet, and the one-time capability is what
# makes delivering over the internet safe. An onboarded host is an authenticated member of a
# closed network; the ACL is the access control and the SHA-256 pin is the integrity, so a uuid
# and a TTL there would be ceremony.
#
# WHY NOT AUTOMATIC: Periphery is the only channel the manager has to a host. An agent that
# upgrades itself can break its own control channel, and the repair is SSH break-glass. Detection
# would work (the Server goes to state != Ok and Komodo alerts), but nothing would fix it — so this
# stays an operator action, taken while somebody is watching.
#
# WHAT IT IMPROVES over the status quo: the host stops fetching Python from GitHub and running it
# as root unverified. The manager fetches it once, checks it against the SHA-256 pinned in
# bootstrap/periphery/versions.env, and inlines the verified bytes into the served script. The host
# fetches nothing from the internet.
#
# Usage:
#   scripts/upgrade-periphery.sh                 # publish for every host behind the Core
#   scripts/upgrade-periphery.sh --host demo     # just one
#   scripts/upgrade-periphery.sh --verify        # poll until versions match, then exit
#   scripts/upgrade-periphery.sh --pin           # print the hash of the current version and stop
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
# shellcheck source=scripts/security-lib.sh
source scripts/security-lib.sh
sec_load_env

PINS="$REPO_DIR/bootstrap/periphery/versions.env"
ONLY=""; MODE="publish"
while [ $# -gt 0 ]; do
  case "$1" in
    --host)   ONLY="${2:?--host needs a name}"; shift 2 ;;
    --verify) MODE="verify"; shift ;;
    --pin)    MODE="pin"; shift ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) sec_die "unknown argument: $1" ;;
  esac
done

# ---- what the fleet should be running -------------------------------------------------------
CORE="$(kapi read/GetVersion '{}' | jq -r '.version // ""')"
[ -n "$CORE" ] || sec_die "could not read the Core version"
SRV="$(kapi read/ListServers '{}')"
jq -e 'type == "array"' >/dev/null <<<"$SRV" || sec_die "ListServers failed"

behind="$(jq -r --arg c "$CORE" --arg only "$ONLY" \
  '.[] | select((.info.version // "") != $c)
       | select($only == "" or .name == $only) | .name' <<<"$SRV")"

if [ "$MODE" = "verify" ]; then
  # Poll rather than assume: an upgrade that did not take is the failure mode that matters, and it
  # is invisible from here unless something asks.
  for _ in $(seq 1 30); do
    SRV="$(kapi read/ListServers '{}' 2>/dev/null || true)"
    left="$(jq -r --arg c "$CORE" '[.[] | select((.info.version // "") != $c) | .name] | join(", ")' <<<"${SRV:-[]}" 2>/dev/null || echo "?")"
    if [ -z "$left" ]; then sec_log "every host matches the Core ($CORE)"; exit 0; fi
    printf '  waiting on: %s\n' "$left"
    sleep 10
  done
  sec_die "still behind after 5 min: $left"
fi

[ -n "$behind" ] || { sec_log "nothing to do: every host already runs $CORE"; exit 0; }

# ---- fetch and VERIFY upstream's installer --------------------------------------------------
URL="https://raw.githubusercontent.com/moghtech/komodo/v${CORE}/scripts/setup-periphery.py"
TMP_PY="$(mktemp)"; trap 'rm -f "$TMP_PY"' EXIT
curl -fsSL --max-time 30 "$URL" -o "$TMP_PY" || sec_die "could not fetch $URL"
GOT="$(sha256sum "$TMP_PY" | cut -d' ' -f1)"
VAR="SETUP_PERIPHERY_v$(tr '.' '_' <<<"$CORE")_SHA256"
WANT="$(sed -n "s/^${VAR}=//p" "$PINS" | head -n1)"

if [ "$MODE" = "pin" ]; then
  echo "  version: v$CORE"
  echo "  url:     $URL"
  echo "  sha256:  $GOT"
  echo "  size:    $(stat -c%s "$TMP_PY") bytes"
  # Independent cross-check, so "satisfy yourself" is backed by something. The raw CDN and the
  # API are different endpoints; the API reports the GIT BLOB SHA-1 that the tag actually points
  # at, which is a statement about the repository rather than about what a CDN served us.
  BLOB="$(git hash-object "$TMP_PY")"
  API="$(curl -fsSL --max-time 30 \
      "https://api.github.com/repos/moghtech/komodo/contents/scripts/setup-periphery.py?ref=v${CORE}" \
      2>/dev/null | jq -r '.sha // ""')"
  echo "  git blob (local):  $BLOB"
  echo "  git blob (at tag): ${API:-<API unreachable>}"
  if [ -n "$API" ] && [ "$BLOB" = "$API" ]; then
    echo "  -> the content matches what tag v${CORE} points at, per two independent endpoints."
  elif [ -n "$API" ]; then
    echo "  -> MISMATCH: the CDN served something the tag does not point at. Do NOT pin this."
    exit 1
  else
    echo "  -> could not reach the API to cross-check; pin on the sha256 alone at your own judgement."
  fi
  echo
  echo "  If satisfied, put this in $PINS:"
  echo "      ${VAR}=${GOT}"
  exit 0
fi

# Fail closed, loudly, on both "no pin" and "wrong pin". An installer that runs as root on every
# host in the fleet is the last place to be relaxed about provenance.
[ -n "$WANT" ] || sec_die "no pin for v$CORE in $PINS — run: $0 --pin"
[ "$GOT" = "$WANT" ] || sec_die "SHA-256 MISMATCH for v$CORE
    expected $WANT
    got      $GOT
  Either upstream changed the file under an existing tag, or the download was tampered with.
  Do NOT re-pin to make this pass without establishing which."
sec_log "setup-periphery.py v$CORE verified against the pin"

# ---- publish, mesh-only ----------------------------------------------------------------------
ART="$REPO_DIR/provisioning/artifacts"
mkdir -p "$ART"
PY_NAME="setup-periphery-v${CORE}.py"
install -m 0644 "$TMP_PY" "${ART}/${PY_NAME}"

# One wrapper for the whole fleet. It is host-agnostic because --connect-as only affects the config
# the installer writes, and we restore ours immediately afterwards -- so there is nothing per-host
# to embed, and therefore no per-host file and no state to expire.
cat > "${ART}/upgrade-periphery.sh" <<WRAP
#!/usr/bin/env bash
# Upgrade Komodo Periphery to match the Core. Generated by scripts/upgrade-periphery.sh on the
# manager; served mesh-only. Run as root on an app host.
set -euo pipefail
[ "\$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
TARGET='v${CORE}'
WANT='${GOT}'
CFG=/etc/komodo/periphery.config.toml

curl -fsSL --max-time 60 "https://apps.internal/artifacts/${PY_NAME}" -o /tmp/setup-periphery.py
# Verified here too. The pin's job is to catch upstream changing under a tag, which the manager
# already checked -- this second check costs nothing and makes the host's step independent of
# trusting the transport it just used.
echo "\${WANT}  /tmp/setup-periphery.py" | sha256sum -c - >/dev/null \\
  || { echo "sha256 mismatch on the installer; refusing" >&2; rm -f /tmp/setup-periphery.py; exit 1; }

# The config carries allowed_ips and the Core's public key, and onboard-host.sh writes it BEFORE
# running the installer on purpose. If the installer rewrites it, put ours back -- otherwise the
# Core loses the host.
BK="\$(mktemp)"; [ -f "\$CFG" ] && cp -a "\$CFG" "\$BK" || true
python3 /tmp/setup-periphery.py --version "\$TARGET" --connect-as "\$(hostname)"
rm -f /tmp/setup-periphery.py
if [ -s "\$BK" ] && ! cmp -s "\$BK" "\$CFG"; then
  echo "installer changed periphery.config.toml — restoring ours"
  cp -a "\$BK" "\$CFG"; chmod 600 "\$CFG"
fi
rm -f "\$BK"

systemctl restart periphery
sleep 2
systemctl is-active periphery
WRAP
chmod 0644 "${ART}/upgrade-periphery.sh"

sec_log "published mesh-only: /artifacts/${PY_NAME} and /artifacts/upgrade-periphery.sh"
echo
echo "  Hosts behind the Core ($CORE):"
while IFS= read -r host; do
  [ -n "$host" ] || continue
  cur="$(jq -r --arg h "$host" '.[] | select(.name==$h) | .info.version // "?"' <<<"$SRV")"
  echo "    $host  ($cur -> $CORE)"
done <<<"$behind"
echo
echo "  On each of them, as root — same command everywhere, no link to copy:"
echo "    sudo bash -c \"\$(curl -fsSL https://apps.internal/artifacts/upgrade-periphery.sh)\""
echo
echo "  Then, here:  $0 --verify"
