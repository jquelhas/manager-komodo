#!/usr/bin/env bash
# Upgrade Komodo Periphery on an app host so it matches the Core. ON DEMAND, never on a timer.
#
# Run on the MANAGER. It does NOT touch any host: the manager deliberately has no SSH to the fleet
# (root SSH from here to every host would be a wider privilege path than anything it protects), so
# this publishes a one-time link and prints the single command to paste on each host that is behind
# — the same "carry, not push" decision as the secaudit bundle.
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

STORE="$REPO_DIR/provisioning/store"
PINS="$REPO_DIR/bootstrap/periphery/versions.env"
TTL="30m"; ONLY=""; MODE="publish"
while [ $# -gt 0 ]; do
  case "$1" in
    --host)   ONLY="${2:?--host needs a name}"; shift 2 ;;
    --ttl)    TTL="${2:?--ttl needs e.g. 30m}"; shift 2 ;;
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

# ---- publish one link per host ---------------------------------------------------------------
[ -d "$STORE" ] || sec_die "store dir $STORE missing (bring provisioning up first)"
[ -w "$STORE" ] || sec_die "store dir $STORE not writable by $(id -un)"
TTL_SECONDS="$(python3 -c "
import re,sys
m=re.match(r'^(\d+)([smh])\$','$TTL')
sys.exit('invalid --ttl') if not m else print(int(m.group(1))*{'s':1,'m':60,'h':3600}[m.group(2)])")"
PUBLIC="$(env_get PUBLIC_DOMAIN)"; PUBLIC="${PUBLIC:-komodo.segcore.eu}"
B64="$(base64 -w0 "$TMP_PY")"

echo
while IFS= read -r host; do
  [ -n "$host" ] || continue
  uuid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  tmp="$(mktemp -d "${STORE}/.tmp.XXXXXX")"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo '[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }'
    echo "TARGET='v${CORE}'; CONNECT_AS='${host}'"
    echo 'CFG=/etc/komodo/periphery.config.toml'
    # The config is written by onboard-host.sh BEFORE the installer runs, on purpose ("so it uses
    # ours"): it carries allowed_ips and the Core's public key. If the installer ever rewrites it,
    # this puts ours back instead of leaving the host unreachable by the Core.
    echo 'BK="$(mktemp)"; [ -f "$CFG" ] && cp -a "$CFG" "$BK" || true'
    echo "printf '%s' '${B64}' | base64 -d > /tmp/setup-periphery.py"
    echo 'python3 /tmp/setup-periphery.py --version "$TARGET" --connect-as "$CONNECT_AS"'
    echo 'rm -f /tmp/setup-periphery.py'
    echo 'if [ -s "$BK" ] && ! cmp -s "$BK" "$CFG"; then'
    echo '  echo "installer changed periphery.config.toml — restoring ours"; cp -a "$BK" "$CFG"; chmod 600 "$CFG"'
    echo 'fi'
    echo 'rm -f "$BK"'
    echo 'systemctl restart periphery'
    echo 'sleep 2; systemctl is-active periphery && /usr/local/bin/periphery --version 2>/dev/null || true'
  } > "${tmp}/install.sh"
  chmod 600 "${tmp}/install.sh"
  now="$(date -u +%s)"
  printf '{"created_at": %s, "expires_at": %s, "role": "periphery-upgrade", "status": "active"}\n' \
    "$now" "$((now + TTL_SECONDS))" > "${tmp}/meta.json"
  chmod 700 "$tmp"; mv "$tmp" "${STORE}/${uuid}"
  cur="$(jq -r --arg h "$host" '.[] | select(.name==$h) | .info.version // "?"' <<<"$SRV")"
  echo "  $host  ($cur -> $CORE), link valid for $TTL:"
  echo "    sudo bash -c \"\$(curl -fsSL https://${PUBLIC}/provisioning/${uuid}/install.sh)\""
  echo
done <<<"$behind"

echo "  Then, here:  $0 --verify"
