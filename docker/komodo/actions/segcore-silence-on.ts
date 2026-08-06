// Komodo Action: open an Alertmanager maintenance silence for the SEGCORE app fleet.
//
// Runs in Komodo Core's Deno runtime, which is on the same `manager-komodo` Docker network as
// Alertmanager, so it POSTs straight to the internal Alertmanager v2 API (no mesh, no auth token).
// The silence is TIME-BOXED: it auto-expires after SILENCE_TTL_MINUTES even if the deploy hangs or
// the paired "off" action never runs, so a silence can never get stuck open and hide real outages.
//
// Installed into Komodo by scripts/setup-deploy-procedure.sh (write/CreateAction) and invoked as
// stage 1 of the `deploy-segcore` Procedure. Paired with segcore-silence-off.ts (stage 3), which
// finds and clears this silence by the createdBy + comment marker below.

const ALERTMANAGER_URL = "http://alertmanager:9093";
const SILENCE_TTL_MINUTES = 30; // upper bound on a deploy (backup + git pull + build + up + migrations)
// Matches every SEGCORE app alert (SegcoreBackendDown, SegcorePostgresExporterDown,
// SegcoreHigh5xxRate[Critical], SegcoreHighLatencyP95) for all segcore hosts during the window.
const MATCHERS = [{ name: "app", value: "segcore", isRegex: false, isEqual: true }];
const CREATED_BY = "komodo"; // marker: (createdBy, comment) is how segcore-silence-off finds this silence
const COMMENT = "segcore deploy";

const now = new Date();
const body = {
  matchers: MATCHERS,
  startsAt: now.toISOString(),
  endsAt: new Date(now.getTime() + SILENCE_TTL_MINUTES * 60_000).toISOString(),
  createdBy: CREATED_BY,
  comment: COMMENT,
};

const res = await fetch(`${ALERTMANAGER_URL}/api/v2/silences`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const text = await res.text();
if (!res.ok) {
  throw new Error(`Alertmanager silence create failed: HTTP ${res.status} ${text}`);
}

let silenceID = text;
try {
  silenceID = JSON.parse(text).silenceID ?? text;
} catch {
  // non-JSON body: keep the raw text as the id for logging
}
console.log(`SEGCORE alerts silenced until ${body.endsAt} (silenceID=${silenceID}).`);
