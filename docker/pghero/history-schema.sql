-- PGHero history tables (created in the manager-owned pghero-postgres store).
-- PGHero has no `rake pghero:prepare` in the Docker image; these are the tables its ActiveRecord
-- models expect, taken verbatim from the gem's guides/Docker.md. Idempotent — safe to run every
-- time (the guide's own version is not, hence the IF NOT EXISTS and the named indexes).
--
-- PGHero 4.0 (2026-08) changed the shape: query text moved out of pghero_query_stats into a
-- deduplicated pghero_queries table, referenced by query_id. That is why the stats table here has
-- `query_id bigint` and no `query` column. The 4.0 upgrade note gives a migration that preserves
-- history; we dropped ours instead (never used, and 514 MB of it), so this file just creates the
-- new shape.
CREATE TABLE IF NOT EXISTS pghero_queries (
  id bigserial PRIMARY KEY,
  query text
);
CREATE INDEX IF NOT EXISTS index_pghero_queries_on_query
  ON pghero_queries USING hash (query);

CREATE TABLE IF NOT EXISTS pghero_query_stats (
  id bigserial PRIMARY KEY,
  database text,
  "user" text,
  query_id bigint,
  query_hash bigint,
  total_time double precision,
  calls bigint,
  captured_at timestamp
);
CREATE INDEX IF NOT EXISTS index_pghero_query_stats_on_database_and_captured_at
  ON pghero_query_stats (database, captured_at);

CREATE TABLE IF NOT EXISTS pghero_space_stats (
  id bigserial PRIMARY KEY,
  database text,
  schema text,
  relation text,
  size bigint,
  captured_at timestamp
);
CREATE INDEX IF NOT EXISTS index_pghero_space_stats_on_database_and_captured_at
  ON pghero_space_stats (database, captured_at);
