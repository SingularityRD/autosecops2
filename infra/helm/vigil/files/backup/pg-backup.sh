#!/bin/sh
# One verified pg_dump of the platform database, then local retention.
#
# Run by the Helm backup CronJob (templates/backup-cronjob.yaml); also runs on
# any host with the PostgreSQL client tools (tests/integration/test_helm_pg_backup.py).
#
# Connection: the libpq variables PGHOST, PGPORT, PGUSER, PGPASSWORD,
# PGDATABASE, PGSSLMODE.
# BACKUP_DIR            where dumps are kept (required)
# BACKUP_KEEP_LAST      newest dumps always kept (default 14, minimum 1)
# BACKUP_RETENTION_DAYS older dumps beyond keep-last are deleted after this
#                       many days; 0 deletes them at once (default 30)
#
# Output: <db>-<UTC timestamp>.dump (custom format) and <dump>.sha256, written
# under a temporary name and renamed only after pg_restore --list reads the
# dump back; LATEST holds the newest dump's file name.
set -eu

: "${BACKUP_DIR:?BACKUP_DIR is required}"
: "${PGDATABASE:?PGDATABASE is required}"
KEEP_LAST="${BACKUP_KEEP_LAST:-14}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
case "$KEEP_LAST" in '' | *[!0-9]*) echo "BACKUP_KEEP_LAST must be a number" >&2; exit 2 ;; esac
case "$RETENTION_DAYS" in '' | *[!0-9]*) echo "BACKUP_RETENTION_DAYS must be a number" >&2; exit 2 ;; esac
[ "$KEEP_LAST" -ge 1 ] || { echo "BACKUP_KEEP_LAST must be at least 1" >&2; exit 2; }

mkdir -p "$BACKUP_DIR"
cd "$BACKUP_DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
name="${PGDATABASE}-${stamp}.dump"
partial=".${name}.partial"
trap 'rm -f "$partial"' EXIT

echo "pg-backup: dumping ${PGDATABASE} on ${PGHOST:-local}:${PGPORT:-5432} to ${BACKUP_DIR}/${name}"
pg_dump --format=custom --compress=6 --file="$partial" --dbname="$PGDATABASE"

# Read the archive back: a truncated or corrupt dump fails here, not at restore.
entries="$(pg_restore --list "$partial" | grep -vc '^;' || true)"
if [ "${entries:-0}" -lt 1 ]; then
    echo "pg-backup: ${name} has no restorable entries" >&2
    exit 1
fi
sha256sum "$partial" | sed "s#  ${partial}\$#  ${name}#" > "${name}.sha256"
mv "$partial" "$name"
printf '%s\n' "$name" > LATEST.tmp && mv LATEST.tmp LATEST
size="$(wc -c < "$name" | tr -d ' ')"
echo "pg-backup: ok ${name} (${size} bytes, ${entries} entries)"

# Retention: the newest KEEP_LAST always stay; any other dump goes once it is
# RETENTION_DAYS old (at once when RETENTION_DAYS is 0).
prefix="${PGDATABASE}-"
find . -maxdepth 1 -type f -name "${prefix}*.dump" | sed 's#^\./##' | sort -r |
    tail -n "+$((KEEP_LAST + 1))" |
    while IFS= read -r old; do
        if [ "$RETENTION_DAYS" -eq 0 ] || [ -n "$(find "./$old" -mmin "+$((RETENTION_DAYS * 1440))")" ]; then
            rm -f -- "$old" "$old.sha256"
            echo "pg-backup: pruned ${old}"
        fi
    done
# Leftovers of runs that died mid-dump.
find . -maxdepth 1 -name '.*.dump.partial' -mmin +1440 -exec rm -f {} + 2>/dev/null || true
