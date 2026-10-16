#!/bin/sh
# Apply every schema/seed file, tolerating failures.
#
# Postgres' own initdb.d runner uses ON_ERROR_STOP=1, so the first failure
# aborts the whole init and leaves a half-built schema — silently, because the
# container then restarts onto the already-initialized data dir and reports
# healthy. Some files here legitimately fail depending on when they run: the
# data-only ones target tables the backend's create_all builds at startup.
#
# Runs twice, from two contexts, which is why it is one script:
#   initdb   — creates extensions and the auth tables (with their DEFAULT
#              clauses, which create_all does not emit) and seeds roles.
#   db-seed  — after create_all, picks up the data whose tables only exist by
#              then. Files use IF NOT EXISTS / ON CONFLICT, so a second pass is
#              a no-op where the first already succeeded; other errors (e.g.
#              trigger already exists) are tolerated.
# Connection comes from libpq env: initdb has POSTGRES_* and a local socket,
# db-seed passes PGHOST/PGUSER/PGDATABASE/PGPASSWORD.
: "${PGUSER:=${POSTGRES_USER}}"
: "${PGDATABASE:=${POSTGRES_DB}}"
export PGUSER PGDATABASE

# Two frozen statements assume the default superuser deeptempo and are
# rewritten as the Helm db-init Job does (its comment says why), so the files
# also apply for a POSTGRES_USER of another name that is not a superuser:
# GRANT ... TO deeptempo goes to CURRENT_USER (the tables' owner), and only a
# superuser runs 30's ALTER ROLE vigil_app NOSUPERUSER. With the default user
# nothing changes.
init_sql() {
    sed -e 's/^\(GRANT .*[[:space:]]TO[[:space:]]*\)deeptempo;/\1CURRENT_USER;/' \
        -e 's/^ALTER ROLE vigil_app NOSUPERUSER LOGIN;$/DO $w$ BEGIN IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN ALTER ROLE vigil_app NOSUPERUSER; END IF; END $w$; ALTER ROLE vigil_app LOGIN;/' \
        "$1"
}

for f in /db-init/*.sql; do
    echo "applying $(basename "$f")"
    init_sql "$f" | psql -v ON_ERROR_STOP=0 -q -f - || true
done

# vigil_app logs in with the password the apps already hold; the SQL file
# cannot contain a literal. :'pw' is interpolated from --set, not -c.
pw="${POSTGRES_PASSWORD:-${PGPASSWORD:-}}"
if [ -n "$pw" ]; then
    echo "setting vigil_app password"
    printf '%s\n' "ALTER ROLE vigil_app PASSWORD :'pw';" \
        | psql -v ON_ERROR_STOP=0 --set=pw="$pw" || true
fi
echo "apply complete"
