#!/usr/bin/env bash
# Starts a throwaway Postgres for the test suite.
#
# The suite needs a live database — RLS and the idempotency invariant are
# database behaviour, and mocking them would test the mock (see ADR-0005,
# ADR-0004). CI provides one as a service; this is for sandboxes and laptops
# that do not have a server running.
#
# Idempotent: safe to run when Postgres is already up.
set -euo pipefail

PGBIN="${PGBIN:-/usr/lib/postgresql/16/bin}"
PGDATA="${PGDATA:-/tmp/pgdata}"
PGSOCK="${PGSOCK:-/tmp/pgrun}"
PGPORT="${PGPORT:-5433}"
PGDB="${PGDB:-driftless_test}"

if "$PGBIN/pg_isready" -h "$PGSOCK" -p "$PGPORT" >/dev/null 2>&1; then
  echo "postgres already accepting connections on $PGSOCK:$PGPORT"
  exit 0
fi

mkdir -p "$PGDATA" "$PGSOCK"
# initdb and pg_ctl refuse to run as root.
if [ "$(id -u)" = "0" ]; then
  chown -R postgres:postgres "$PGDATA" "$PGSOCK"
  chmod 700 "$PGDATA"
  RUN="su postgres -c"
else
  RUN="bash -c"
fi

if [ ! -f "$PGDATA/PG_VERSION" ]; then
  $RUN "$PGBIN/initdb -D $PGDATA -U postgres --auth=trust" >/dev/null
fi

$RUN "$PGBIN/pg_ctl -D $PGDATA -l $PGDATA/server.log -o '-p $PGPORT -k $PGSOCK' start" >/dev/null
for _ in $(seq 1 20); do
  "$PGBIN/pg_isready" -h "$PGSOCK" -p "$PGPORT" >/dev/null 2>&1 && break
  sleep 0.5
done

$RUN "$PGBIN/createdb -h $PGSOCK -p $PGPORT $PGDB" 2>/dev/null || true
echo "postgres ready on $PGSOCK:$PGPORT (database: $PGDB)"
