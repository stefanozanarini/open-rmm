#!/bin/sh
# Creates the open-rmm database owned by a dedicated, non-superuser role:
# the console refuses to run as a superuser because it would bypass the
# row-level security that isolates tenants. Runs only on first start.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
  --set=pw="$OPENRMM_DB_PASSWORD" <<'SQL'
CREATE ROLE openrmm LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'pw';
CREATE DATABASE openrmm OWNER openrmm;
REVOKE ALL ON DATABASE openrmm FROM PUBLIC;
SQL
