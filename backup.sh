#!/bin/bash
set -e

# Backup configuration
BACKUP_DIR="/var/backups/clockwork"
S3_BUCKET="clockwork-backups"
DATE=$(date +%Y%m%d-%H%M%S)
DB_BACKUP_FILE="db-backup-${DATE}.sql"
FILES_BACKUP_FILE="files-backup-${DATE}.tar.gz"

# Create backup directory
mkdir -p ${BACKUP_DIR}

echo "Starting backup process..."

# Database backup
echo "Backing up database..."
pg_dump ${DATABASE_URL} > ${BACKUP_DIR}/${DB_BACKUP_FILE}
gzip ${BACKUP_DIR}/${DB_BACKUP_FILE}

# Files backup (uploads, etc.)
echo "Backing up files..."
tar -czf ${BACKUP_DIR}/${FILES_BACKUP_FILE} /var/www/clockwork-backend/uploads

# Upload to S3
echo "Uploading to S3..."
aws s3 cp ${BACKUP_DIR}/${DB_BACKUP_FILE}.gz s3://${S3_BUCKET}/database/
aws s3 cp ${BACKUP_DIR}/${FILES_BACKUP_FILE} s3://${S3_BUCKET}/files/

# Clean up old local backups (keep last 7 days)
find ${BACKUP_DIR} -name "*.gz" -mtime +7 -delete

# Verify backup
if aws s3 ls s3://${S3_BUCKET}/database/${DB_BACKUP_FILE}.gz; then
    echo "✅ Backup completed successfully!"
    
    # Send notification
    curl -X POST ${SLACK_WEBHOOK_URL} \
      -H 'Content-type: application/json' \
      --data "{\"text\":\"✅ ClockWork backup completed successfully - ${DATE}\"}"
else
    echo "❌ Backup failed!"
    
    # Send alert
    curl -X POST ${SLACK_WEBHOOK_URL} \
      -H 'Content-type: application/json' \
      --data "{\"text\":\"🚨 ClockWork backup FAILED - ${DATE}\"}"
    
    exit 1
fi