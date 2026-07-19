# PGHero — application-host setup (GIMSv2)

This is everything **each app host** (`tag:segcore`) must have so the manager's PGHero can analyse
its PostgreSQL. These changes live in the **GIMSv2 repo / host config**, not in `manager-komodo`.
Do them once per host (ideally fold into the app's bootstrap so new hosts inherit them).

The manager connects **read-only** (`pg_monitor`) over the mesh to port 5432. It never gets write or
master credentials. See `docs/DESIGN.md` → "Acesso PGHero à 5432" for the security model.

---

## 1. Enable `pg_stat_statements` (needed for "worst queries"; requires a restart)

In `postgresql.conf` (or an included fragment):

```conf
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track  = all
pg_stat_statements.max    = 10000
```

`shared_preload_libraries` only takes effect after a **full Postgres restart** (not a reload).

Then create the extension **in every database you want analysed** — it is per-database. For the
`gims_*` tenant databases, e.g. run as a superuser (the `postgres` role):

```sql
-- one-off, per target database
\c gims_acme
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

Or loop over all matching databases from the shell:

```bash
for db in $(psql -U postgres -Atqc "SELECT datname FROM pg_database WHERE datname LIKE 'gims_%' AND datallowconn AND NOT datistemplate"); do
  psql -U postgres -d "$db" -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
done
```

## 2. Create the read-only monitoring role

Once per cluster. Role name `monitor`; its password **must equal** `PGHERO_DB_PASSWORD` in the
manager's `.env` (same role+password on every host, so the manager keeps a single secret):

```sql
CREATE ROLE monitor LOGIN PASSWORD 'REPLACE_WITH_PGHERO_DB_PASSWORD';
GRANT pg_monitor TO monitor;   -- read-all-stats + read-all-settings; enough for slow queries,
                               -- index usage and bloat. No write, no EXPLAIN of real queries.
```

Grant `CONNECT` on each target database (and on `postgres`, which the manager uses only to
*enumerate* the `gims_*` databases — usually already granted to `PUBLIC`, but be explicit if your
setup revokes it):

```sql
GRANT CONNECT ON DATABASE postgres  TO monitor;   -- for database enumeration
-- per target database:
GRANT CONNECT ON DATABASE gims_acme TO monitor;
```

Loop form:

```bash
psql -U postgres -c "GRANT CONNECT ON DATABASE postgres TO monitor;"
for db in $(psql -U postgres -Atqc "SELECT datname FROM pg_database WHERE datname LIKE 'gims_%' AND datallowconn AND NOT datistemplate"); do
  psql -U postgres -c "GRANT CONNECT ON DATABASE \"$db\" TO monitor;"
done
```

> `pg_monitor` covers reading `pg_stat_statements`, index/table stats and settings. Do **not** grant
> more — keep it read-only.

### 2b. (Optional) Query-stats history — grant `pg_stat_statements_reset`

`pg_monitor` is enough for **live** analysis (worst queries, missing/unused indexes, bloat,
connections). But PGHero's **historical** query stats work by resetting `pg_stat_statements` after
each hourly capture (to measure per-interval deltas) — and `pg_monitor` does **not** grant execute on
the reset function. Without this grant, the live "Queries" page still works; only the query-stats
*history over time* is unavailable (space/table-growth history works regardless).

If you want query-stats history, grant execute on the reset function **in each target database**
(the function lives where the extension is installed). Signature depends on the PostgreSQL version:

```sql
-- PostgreSQL 17 / 18 (adds the minmax_only arg):
GRANT EXECUTE ON FUNCTION pg_stat_statements_reset(oid, oid, bigint, boolean) TO monitor;
-- PostgreSQL 13–16:
-- GRANT EXECUTE ON FUNCTION pg_stat_statements_reset(oid, oid, bigint) TO monitor;
```

Loop form (PG17/18):

```bash
for db in $(psql -U postgres -Atqc "SELECT datname FROM pg_database WHERE datname LIKE 'gims_%' AND datallowconn AND NOT datistemplate"); do
  psql -U postgres -d "$db" -c "GRANT EXECUTE ON FUNCTION pg_stat_statements_reset(oid, oid, bigint, boolean) TO monitor;"
done
```

> **Trade-off (your call):** with this grant, PGHero resets each analysed database's
> `pg_stat_statements` **once per hour** (per-database on PG12+, so other databases are untouched).
> Anyone doing ad-hoc `SELECT * FROM pg_stat_statements` on those databases then only sees ~1h of
> data. The `postgres-exporter` dashboards do **not** use `pg_stat_statements`, so they are unaffected.
> Skip this grant if you prefer to keep `pg_stat_statements` cumulative and live with live-only query
> analysis (no query-stats history).

## 3. Allow the manager in `pg_hba.conf`

Postgres already listens on the host's mesh IP (`${LOCAL_BIND_IP}`; the operator laptop already does
`psql`). Only authorise the `monitor` role from the manager's mesh IP. Add **above** any broad
`reject`/catch-all line:

```
# PGHero read-only analysis from the manager (mesh IP 100.64.0.1)
host    all    monitor    100.64.0.1/32    scram-sha-256
```

Then reload (no restart needed for `pg_hba`):

```bash
psql -U postgres -c "SELECT pg_reload_conf();"
```

## 4. Mesh ACL (already done on the manager)

`manager-komodo/docker/headscale/acl.hujson` now allows `tag:manager → tag:segcore:...,5432`.
After pulling that change on the manager, reload the Headscale policy so the manager can reach 5432.

---

## Verify (from the app host)

```bash
# extension present in a target DB:
psql -U monitor -d gims_acme -c "SELECT count(*) FROM pg_stat_statements;"
```

## Verify (from the manager)

```bash
# reachability + auth over the mesh (replace <mesh_ip>/<db>):
psql "postgres://monitor:${PGHERO_DB_PASSWORD}@<mesh_ip>:5432/gims_acme?connect_timeout=5" -c "select 1;"
```

Once these pass, PGHero on the manager will list the host's databases automatically (the config is
generated from the Komodo fleet by `pghero-init`; run `scripts/pghero-refresh.sh` after onboarding a
new host to pick it up immediately).

---

## Host-side checklist

- [ ] `shared_preload_libraries = 'pg_stat_statements'` in `postgresql.conf` **+ restart**
- [ ] `CREATE EXTENSION pg_stat_statements` in each `gims_*` database
- [ ] `CREATE ROLE monitor` with the shared `PGHERO_DB_PASSWORD` + `GRANT pg_monitor`
- [ ] `GRANT CONNECT` on `postgres` + each `gims_*` database to `monitor`
- [ ] `pg_hba.conf` line for `monitor` from `100.64.0.1/32` **+ reload**
- [ ] *(optional, for query-stats history)* `GRANT EXECUTE ON FUNCTION pg_stat_statements_reset(...)` to `monitor` in each `gims_*` database
