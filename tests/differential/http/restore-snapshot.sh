#!/bin/sh
# Postgres init hook: restore the shared snapshot into a fresh database.
set -eu
pg_restore --no-owner --role="$POSTGRES_USER" -U "$POSTGRES_USER" -d "$POSTGRES_DB" /snapshot/snapshot.dump
