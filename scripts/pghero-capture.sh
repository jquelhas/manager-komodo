#!/usr/bin/env bash
# Capture PGHero query/space stats into its history store (pghero-postgres), building the historical
# view the UI shows over time. Scheduled hourly by manager-pghero-capture.timer.
#
# On-demand analysis needs no capture — the UI reads pg_stat_statements/catalog live. Captures only
# feed the *history* (evolution over time). To trigger a capture by hand, just run this script.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# Ensure the history tables exist in pghero-postgres (idempotent; PGHero 3.x has no pghero:prepare).
docker compose exec -T pghero-postgres psql -U "${PGHERO_HISTORY_DB_USERNAME:-pghero}" -d pghero \
  -v ON_ERROR_STOP=1 -f - < docker/pghero/history-schema.sql >/dev/null

# Query-stats history is optional: it needs EXECUTE on pg_stat_statements_reset on each host (see
# docs/pghero-host-setup.md § 2b). Keep it non-fatal so the timer doesn't fail hourly before that
# grant exists — live query analysis in the UI works regardless.
docker compose exec -T pghero bin/rake pghero:capture_query_stats || \
  echo "WARN: query-stats capture failed — grant pg_stat_statements_reset to 'monitor' on the app hosts to enable query history (docs/pghero-host-setup.md § 2b)" >&2

# Space/table-growth history only needs pg_monitor — a failure here is a real problem, so keep it fatal.
docker compose exec -T pghero bin/rake pghero:capture_space_stats
