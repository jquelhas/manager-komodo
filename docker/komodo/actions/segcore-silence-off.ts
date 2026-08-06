// Komodo Action: clear the Alertmanager maintenance silence opened by segcore-silence-on.ts.
//
// It matches the silence by MARKER (createdBy + comment prefix) rather than by a silence id, so no
// state has to be passed between Procedure stages (Komodo Actions don't share state natively). A
// missing or already-expired silence is a no-op — the paired "on" action also time-boxes the
// silence, so even if this action never runs the silence clears itself.
//
// Installed by scripts/setup-deploy-procedure.sh (write/CreateAction) and invoked as stage 3 of the
// `deploy-segcore` Procedure.

const ALERTMANAGER_URL = "http://alertmanager:9093";
const CREATED_BY = "komodo";
const COMMENT_PREFIX = "segcore deploy";

const listRes = await fetch(`${ALERTMANAGER_URL}/api/v2/silences`);
if (!listRes.ok) {
  throw new Error(`Alertmanager list silences failed: HTTP ${listRes.status} ${await listRes.text()}`);
}
const silences = await listRes.json();

const ours = (Array.isArray(silences) ? silences : []).filter(
  (s) =>
    s?.status?.state === "active" &&
    s?.createdBy === CREATED_BY &&
    typeof s?.comment === "string" &&
    s.comment.startsWith(COMMENT_PREFIX),
);

if (ours.length === 0) {
  console.log("No active SEGCORE deploy silence to clear.");
} else {
  for (const s of ours) {
    const del = await fetch(`${ALERTMANAGER_URL}/api/v2/silences/${s.id}`, { method: "DELETE" });
    if (!del.ok) {
      throw new Error(`Failed to delete silence ${s.id}: HTTP ${del.status} ${await del.text()}`);
    }
    console.log(`Cleared SEGCORE deploy silence ${s.id}.`);
  }
}
