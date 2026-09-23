#!/bin/sh
set -eu
umask 077
# Deliberately no scheduler, retries, cloud initialization or pruning here.
test "${BACKUP_ENABLED:-0}" = 1 || { echo 'Backup disabled' >&2; exit 78; }
test -n "${RESTIC_REPOSITORY:-}"
test -r "$RESTIC_PASSWORD_FILE"
test -r "$AWS_SHARED_CREDENTIALS_FILE"
test -d /sources
test -n "$(ls -A /sources)"
test -w /state
test -w /cache
# Exit code 3 (unreadable files) is a failure, not a partial success.
if test "${STORAGE_CLASS:-}" = DEEP_ARCHIVE; then
    restic -o s3.storage-class=DEEP_ARCHIVE backup --host nas --tag weekly /sources
else
    test "${STORAGE_CLASS:-}" = STANDARD
    restic backup --host nas --tag weekly /sources
fi
# Metadata check only. Do not automatically read/thaw archived data packs.
restic check
date -u +%s > /state/last-success.new
mv /state/last-success.new /state/last-success
echo 'Backup and metadata check completed'
