# pghero-init: renders PGHero's multi-database config from the live Komodo fleet.
# Needs a Postgres client (to enumerate databases per host) + Python stdlib (HTTP + JSON + YAML
# emit). postgres:18-alpine ships psql; add python3 (stdlib only, no pip). Pinned to the same
# major as the rest of the fleet's Postgres tooling.
FROM postgres:18-alpine

RUN apk add --no-cache python3

COPY generate-config.py /generate-config.py

# Non-root: the shared /config volume is written as this uid.
USER 1000:1000

ENTRYPOINT ["python3", "/generate-config.py"]
