#!/usr/bin/env sh
# Nightly PostgreSQL backup. Install with:  crontab -e
#   15 2 * * * /opt/kidguard/backend/deploy/hetzner/backup.sh >> /var/log/kidguard-backup.log 2>&1
# Keeps 14 daily dumps locally. Copy them off-server too (Hetzner Storage Box / S3).
set -eu
cd "$(dirname "$0")"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/kidguard}"
mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=9' > "$BACKUP_DIR/kidguard-$STAMP.dump"
find "$BACKUP_DIR" -name 'kidguard-*.dump' -mtime +14 -delete
echo "Backup written: $BACKUP_DIR/kidguard-$STAMP.dump"
