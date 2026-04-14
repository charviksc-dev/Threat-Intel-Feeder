# Backup Strategy for Neev Threat Intelligence Platform

## Overview

This document outlines the backup and disaster recovery strategy for the Neev Threat Intelligence Platform. The platform consists of three critical data stores that require regular backups:

1. **PostgreSQL** - User data, metadata, audit logs, configurations
2. **Elasticsearch** - IOC index, search data
3. **Redis** - Cache, Celery broker (transient data, less critical)

---

## PostgreSQL Backup Strategy

### Backup Requirements
- **Frequency**: Daily full backups + hourly transaction log backups
- **Retention**: 30 days daily, 7 days hourly
- **Recovery Time Objective (RTO)**: 1 hour
- **Recovery Point Objective (RPO)**: 15 minutes

### Backup Methods

#### 1. Physical Backup (pg_dump) - Recommended for Small/Medium Deployments

```bash
# Daily full backup
docker exec neev-postgres pg_dump -U neev neev | gzip > /backups/postgres/neev-$(date +%Y%m%d).sql.gz

# Hourly transaction log backup
docker exec neev-postgres pg_dump -U neev neev --format=custom --file=/tmp/neev-$(date +%Y%m%d-%H).dump
```

#### 2. WAL Archiving - Recommended for Production

Add to `docker-compose.yml`:

```yaml
postgres:
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - postgres_wal:/var/lib/postgresql/wal
  command:
    - postgres
    - -c
    - wal_level=replica
    - -c
    - archive_mode=on
    - -c
    - archive_command='cp %p /var/lib/postgresql/wal/%f'
```

### Backup Script

Create `scripts/backup-postgres.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d-%H%M%S)
CONTAINER="neev-postgres"
USER="neev"
DB="neev"

mkdir -p $BACKUP_DIR

# Full backup
docker exec $CONTAINER pg_dump -U $USER $DB | gzip > $BACKUP_DIR/neev-full-$DATE.sql.gz

# Keep last 30 days
find $BACKUP_DIR -name "neev-full-*.sql.gz" -mtime +30 -delete

echo "PostgreSQL backup completed: $BACKUP_DIR/neev-full-$DATE.sql.gz"
```

### Restore Procedure

```bash
# Stop application
docker compose stop api worker

# Restore from backup
gunzip < /backups/postgres/neev-20240414-000000.sql.gz | docker exec -i neev-postgres psql -U neev neev

# Restart application
docker compose start api worker
```

---

## Elasticsearch Backup Strategy

### Backup Requirements
- **Frequency**: Daily snapshots
- **Retention**: 7 days
- **RTO**: 2 hours
- **RPO**: 24 hours

### Snapshot Repository Configuration

First, register a snapshot repository (using shared file system):

```bash
# Create backup directory
mkdir -p /backups/elasticsearch
chmod 777 /backups/elasticsearch

# Register repository
curl -X PUT "localhost:9200/_snapshot/backup_repo" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backups/elasticsearch"
  }
}'
```

Add to docker-compose.yml:

```yaml
elasticsearch:
  volumes:
    - es_data:/usr/share/elasticsearch/data
    - /backups/elasticsearch:/backups/elasticsearch
```

### Backup Script

Create `scripts/backup-elasticsearch.sh`:

```bash
#!/bin/bash
DATE=$(date +%Y%m%d-%H%M%S)
SNAPSHOT_NAME="neev-snapshot-$DATE"

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup_repo/$SNAPSHOT_NAME?wait_for_completion=true"

# Delete snapshots older than 7 days
curl -X DELETE "localhost:9200/_snapshot/backup_repo/_all" -d'
{
  "conditions": {
    "max_age": "7d"
  }
}'

echo "Elasticsearch snapshot completed: $SNAPSHOT_NAME"
```

### Restore Procedure

```bash
# Close all indices
curl -X POST "localhost:9200/_all/close"

# Restore from snapshot
curl -X POST "localhost:9200/_snapshot/backup_repo/neev-snapshot-20240414-000000/_restore"

# Open indices
curl -X POST "localhost:9200/_all/open"
```

---

## Redis Backup Strategy

### Backup Requirements
- **Frequency**: Daily (optional - Redis is cache/transient)
- **Retention**: 3 days
- **RTO**: 30 minutes
- **RPO**: 24 hours

### Backup Method

Redis data is primarily cache and Celery broker data. Full backup is optional but recommended for Celery task recovery.

```bash
# Save RDB snapshot
docker exec neev-redis redis-cli BGSAVE

# Copy RDB file
docker cp neev-redis:/data/dump.rdb /backups/redis/dump-$(date +%Y%m%d).rdb
```

---

## Automated Backup Schedule

### Cron Jobs

Add to crontab (`crontab -e`):

```cron
# PostgreSQL - Daily at 2 AM
0 2 * * * /path/to/scripts/backup-postgres.sh >> /var/log/backups/postgres.log 2>&1

# PostgreSQL - Hourly transaction log
0 * * * * docker exec neev-postgres pg_dump -U neev neev --format=custom --file=/tmp/neev-hourly.dump && mv /tmp/neev-hourly.dump /backups/postgres/neev-hourly-$(date +\%Y\%m\%d-\%H).dump

# Elasticsearch - Daily at 3 AM
0 3 * * * /path/to/scripts/backup-elasticsearch.sh >> /var/log/backups/elasticsearch.log 2>&1

# Redis - Daily at 4 AM
0 4 * * * docker exec neev-redis redis-cli BGSAVE && docker cp neev-redis:/data/dump.rdb /backups/redis/dump-$(date +\%Y\%m\%d).rdb >> /var/log/backups/redis.log 2>&1
```

---

## Cloud Storage Integration (Optional)

For production deployments, consider syncing backups to cloud storage:

### AWS S3

```bash
# Install AWS CLI
pip install awscli

# Sync PostgreSQL backups
aws s3 sync /backups/postgres s3://your-bucket/neev-backups/postgres

# Sync Elasticsearch snapshots
aws s3 sync /backups/elasticsearch s3://your-bucket/neev-backups/elasticsearch
```

### Google Cloud Storage

```bash
# Install gsutil
pip install gsutil

# Sync backups
gsutil -m rsync -r /backups/postgres gs://your-bucket/neev-backups/postgres
```

---

## Disaster Recovery Procedure

### Scenario 1: PostgreSQL Failure

1. **Detection**: Health check fails or database unreachable
2. **Action**:
   ```bash
   # Stop application
   docker compose stop api worker
   
   # Restore latest backup
   gunzip < /backups/postgres/neev-full-$(ls -t /backups/postgres/*.sql.gz | head -1 | xargs -n1 basename) | docker exec -i neev-postgres psql -U neev neev
   
   # Restart application
   docker compose start api worker
   ```
3. **Verification**: Check application health endpoint
4. **RPO**: Data loss up to last backup (15 minutes with hourly logs)

### Scenario 2: Elasticsearch Failure

1. **Detection**: Search queries fail, health check degraded
2. **Action**:
   ```bash
   # Restore from latest snapshot
   curl -X POST "localhost:9200/_snapshot/backup_repo/_latest_snapshot/_restore"
   ```
3. **Verification**: Test search functionality
4. **RPO**: Data loss up to last snapshot (24 hours)

### Scenario 3: Complete System Failure

1. **Detection**: All services down
2. **Action**:
   - Restore PostgreSQL from latest backup
   - Restore Elasticsearch from latest snapshot
   - Restart all services
3. **Verification**: Full system health check
4. **RTO**: 2-3 hours

---

## Monitoring Backup Health

### Backup Verification Script

Create `scripts/verify-backups.sh`:

```bash
#!/bin/bash

# Check PostgreSQL backup exists and is recent
POSTGRES_BACKUP=$(ls -t /backups/postgres/neev-full-*.sql.gz | head -1)
if [ -z "$POSTGRES_BACKUP" ]; then
    echo "ERROR: No PostgreSQL backup found"
    exit 1
fi

POSTGRES_AGE=$(( ($(date +%s) - $(stat -c %Y "$POSTGRES_BACKUP")) / 86400 ))
if [ $POSTGRES_AGE -gt 2 ]; then
    echo "WARNING: PostgreSQL backup is $POSTGRES_AGE days old"
fi

# Check Elasticsearch snapshot exists
ES_SNAPSHOTS=$(curl -s "localhost:9200/_snapshot/backup_repo/_all" | jq -r '.snapshots | length')
if [ "$ES_SNAPSHOTS" -eq 0 ]; then
    echo "ERROR: No Elasticsearch snapshots found"
    exit 1
fi

echo "Backup verification passed"
```

Add to cron to run daily after backups.

---

## Testing Backups

### Monthly Restore Test

Perform a monthly test restore to ensure backup integrity:

1. Spin up test environment
2. Restore latest backups
3. Verify data integrity
4. Document results

---

## Security Considerations

1. **Encryption**: Encrypt backups at rest using LUKS or cloud storage encryption
2. **Access Control**: Restrict backup directory access to backup user only
3. **Secure Transfer**: Use SSL/TLS for cloud storage transfers
4. **Key Management**: Store encryption keys separately from backups
5. **Audit**: Log all backup and restore operations

---

## Contact Information

- **Backup Administrator**: [email]
- **On-Call**: [phone]
- **Escalation**: [email]

---

## Document History

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2024-04-14 | 1.0 | Initial version | Product Team |
