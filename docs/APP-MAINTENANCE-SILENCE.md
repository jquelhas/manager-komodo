# Maintenance silence in `update.sh` — brief for the application team

This is a hand-over document, like `docs/CI-IMAGE-SCANNING.md`. It asks for one small change to
`scripts/update.sh` in the application repository. The control-plane side is already built,
deployed and tested; nothing here is speculative.

## The problem it fixes

`update.sh` stops the whole compose project in step 2 and brings it back in step 7. The application
is therefore down for roughly ten minutes, on purpose. The control plane cannot tell that apart
from a real outage, so it does what it should: `SegcoreBackendDown` fires after 2 minutes and
`SegcorePostgresExporterDown` after 5, and the operator gets about four e-mails per deploy — two
firing, two resolved.

That is worse than merely annoying. E-mails about planned downs teach people to ignore e-mails
about downs, and that is how a real outage gets missed.

The control plane already had a way to suppress this, but it only worked when the deploy was
started from one particular button in the Komodo UI. Deploys also happen from two other places —
the resource's own *Deploy*/*Pull* button, and `./scripts/update.sh` run by hand over SSH — and
neither was covered. **The silence belongs to the deploy, not to whichever path triggered it**,
which means it belongs in this script.

## What to add

Two `curl` calls, and a guard so the script behaves identically when the feature is not
configured.

```bash
# --- maintenance silence (control plane) ---------------------------------------
# Ask the control plane to silence THIS host's alerts while we rebuild. The URL comes from the
# .env that Komodo writes; empty or absent means the feature is off, and the deploy proceeds
# exactly as before. Never fails the deploy: see "Failure is not an error" below.
silence() {
    [ -n "${KOMODO_ALERT_SILENCE_URL:-}" ] || return 0
    curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
         -d "${2:-\{\}}" "${KOMODO_ALERT_SILENCE_URL}/$1" >/dev/null 2>&1 \
      || echo "     AVISO: silence/$1 falhou — o deploy continua, esperar e-mails de down/up"
}
```

Then one call before the work starts and one after the final verification:

```bash
silence start '{"minutes":45,"reason":"update.sh"}'   # before [1/7], after the .env validation
# … the seven steps and the final verification …
silence end                                            # at the very end, always
```

Place `silence start` **after** the `.env` validation block (it needs `$KOMODO_ALERT_SILENCE_URL`,
which comes from the `.env`) and **before** step 1, so the silence is in place before anything
stops. Place `silence end` after the final verification, so a failed verification is still
reported while the silence is lifted.

### Four properties you can rely on

- **`minutes` is capped server-side at 45.** Ask for more and you get 45, reported back in the JSON
  response. The cap is what stops an `update.sh` that dies mid-run from leaving the host
  unmonitored: `silence end` is the prompt cleanup, the cap is the safety net. 45 minutes is triple
  the slowest update measured (~15 min).
- **`start` is idempotent.** Calling it twice replaces the silence rather than stacking a second
  one. Without that, a retried deploy would leave a silence that `end` does not clear.
- **`end` is idempotent.** With nothing to expire it returns `200 {"expired": 0}`, not `404`. The
  script calls it unconditionally, and a 404 in every clean deploy's log is noise that teaches
  people to stop reading logs.
- **You cannot silence another host, or anything other than this application.** The endpoint takes
  no matchers and rejects a `host` field with `400`. Which host is being silenced is derived from
  the token in the URL, which is specific to this host.

### Failure is not an error

The `|| echo AVISO` is deliberate and must stay. If the control plane is unreachable — down,
mid-upgrade, mesh problem — the deploy must still run to completion. A host has to remain
updatable with no control plane at all; making the deploy depend on it would trade a real
capability for four e-mails.

The same reasoning covers the `[ -n ... ] || return 0` guard: a checkout with no
`KOMODO_ALERT_SILENCE_URL` (a developer machine, a host not yet enrolled, the variable
deliberately cleared) behaves exactly as the script does today.

## What you do not have to do

- **Nothing to store in the repository, and no credential to handle in code.** The URL you read
  from the `.env` already ends in this host's token, and treating the whole string as opaque is all
  that is required. Do not parse it, log it, or echo it: it is the credential.
- **No new variable to maintain.** `KOMODO_ALERT_SILENCE_URL` is written into `/opt/SEGCORE/.env`
  by Komodo. Just read it.
- **No TLS configuration.** The host trusts the control plane's internal CA, so a plain `curl`
  works with no `--cacert` and no certificate path to keep in step.
- **No retries, no backoff, no state.** Two fire-and-forget POSTs.

## How to check it worked

From the host, with the app's `.env` sourced:

```bash
curl -fsS -X POST -H 'Content-Type: application/json' -d '{"minutes":5}' \
     "$KOMODO_ALERT_SILENCE_URL/start"
# {"ok": true, "host": "segcore-demo", "silence_id": "…", "minutes": 5, "ends_at": "…"}

curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' \
     "$KOMODO_ALERT_SILENCE_URL/end"
# {"ok": true, "host": "segcore-demo", "expired": 1}
```

The response names the host the control plane attributed the request to. If that is not this host,
stop and report it — it would mean the address mapping is wrong, and the wrong host's alerts would
be silenced.

Error responses, for the record: `403` the token is not recognised (or the request did not come
through the control plane's proxy), `400` a `host` field was sent, `502` Alertmanager did not
answer, `503` the endpoint is switched off or not configured at the control plane.

## Correction, 2026-09-08

An earlier version of this brief said there was no token, because the control plane would identify
the caller by its Tailscale mesh address. **That does not work, and it was measured rather than
assumed:** a request from an application host reaches the control plane's proxy with
`X-Forwarded-For: 172.18.0.1` — the manager's Docker bridge gateway — because dockerd's userland
proxy terminates the incoming connection and opens a fresh one towards the container. Every host
therefore looks identical at the application layer, so an address-based check authenticates nobody.

The fix put a per-host token in the URL path, which is why **nothing in this brief's code changed**:
`"${KOMODO_ALERT_SILENCE_URL}/start"` carries the token for free. If you already implemented the
snippet above, there is nothing to do.
