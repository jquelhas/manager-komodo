-- PGHero history tables (created in the manager-owned pghero-postgres store).
-- PGHero 3.x has no `rake pghero:prepare`; these are the tables its ActiveRecord models expect
-- (schema matches the gem's Rails migration generators). Idempotent — safe to run every time.
CREATE TABLE IF NOT EXISTS pghero_query_stats (
  id bigserial PRIMARY KEY,
  database text,
  "user" text,
  query text,
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
