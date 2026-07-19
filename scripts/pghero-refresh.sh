#!/usr/bin/env bash
# Re-render PGHero's database config from the live Komodo fleet (docker/pghero/generated/pghero.yml),
# picking up newly onboarded hosts / databases, then reload PGHero so it reads the new list.
#
# Run after onboarding a host with app databases, or let manager-pghero-refresh.timer do it daily.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# Regenerate the config from the fleet (one-shot; --rm cleans up the container).
docker compose run --rm pghero-init

# Ensure the history tables exist (idempotent), then reload PGHero to pick up the new config.
docker compose exec -T pghero-postgres psql -U "${PGHERO_HISTORY_DB_USERNAME:-pghero}" -d pghero \
  -v ON_ERROR_STOP=1 -f - < docker/pghero/history-schema.sql >/dev/null 2>&1 || true
docker compose restart pghero
