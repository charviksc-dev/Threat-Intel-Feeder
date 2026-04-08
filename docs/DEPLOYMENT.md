# Neev TIP — Production Deployment Guide

## Prerequisites
- Docker & Docker Compose v2
- Minimum 4GB RAM for all services
- Access to TheHive (port 9000) and Cortex (port 9001) instances

## Quick Start

### 1. Configure Environment
```bash
cp .env.example .env
# Generate secrets:
python3 -c "import secrets; print(secrets.token_urlsafe(64))"  # → SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"       # → WEBHOOK_AUTH_TOKEN
openssl rand -base64 32                                          # → POSTGRES_PASSWORD
```

### 2. Configure SIEM Integrations
Edit `.env` with your actual values:
```
THEHIVE_URL=http://10.81.20.144:9000
THEHIVE_API_KEY=<your-thehive-api-key>
CORTEX_URL=http://10.81.20.144:9001
CORTEX_API_KEY=<your-cortex-api-key>
```

### 3. Start the Platform
```bash
docker compose up -d --build
```

### 4. Verify Health
```bash
curl http://localhost:8000/api/v1/health
# → {"status":"ok","version":"2.1.0","env":"production"}
```

### 5. Configure Wazuh Webhook
In Wazuh `ossec.conf`:
```xml
<integration>
  <name>custom-api</name>
  <hook_url>http://YOUR_HOST:8000/api/v1/integrations/wazuh/webhook</hook_url>
  <alert_format>json</alert_format>
  <api_key>YOUR_WEBHOOK_AUTH_TOKEN</api_key>
</integration>
```

SIEM tools must include the webhook token:
```bash
curl -X POST http://localhost:8000/api/v1/integrations/wazuh/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: YOUR_WEBHOOK_AUTH_TOKEN" \
  -d '{"rule": {"level": 10, "description": "Test alert"}, "agent": {"name": "test"}}'
```

## Architecture

```
                    ┌──────────┐
                    │  nginx   │ :80/:443
                    └────┬─────┘
                    ┌────┴──────────────────┐
                    │                       │
              ┌─────▼─────┐          ┌──────▼─────┐
              │  UI :80   │          │  API :8000  │
              │ (nginx)   │          │ (FastAPI)   │
              └───────────┘          └──────┬──────┘
                                     ┌──────┼──────┐
                               ┌─────▼──┐ ┌─▼───┐ ┌▼────────────┐
                               │Postgres│ │Redis│ │Elasticsearch│
                               │  :5432 │ │:6379│ │   :9200     │
                               └────────┘ └──┬──┘ └─────────────┘
                                             │
                                    ┌────────▼────────┐
                                    │  Worker (Celery) │
                                    │  Beat (Scheduler)│
                                    └─────────────────┘
```

## Services

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| API | neev-api | 8000 | FastAPI gateway |
| Worker | neev-worker | — | Feed ingestion |
| Beat | neev-beat | — | Scheduled tasks |
| UI | neev-ui | 4173→80 | React dashboard |
| PostgreSQL | neev-postgres | 5432 | Metadata/RBAC |
| Redis | neev-redis | 6379 | Task broker |
| Elasticsearch | neev-elasticsearch | 9200 | IOC storage |
| nginx | neev-nginx | 80/443 | Reverse proxy |

## Feed Sync Schedule

| Feed | Schedule | API Key Required |
|------|----------|-----------------|
| Free feeds (7) | Every 30 min | No |
| OTX | Every 2 hours | Yes |
| VirusTotal | Every 4 hours | Yes |
| Full sync (all 12) | Hourly | Mixed |

## Monitoring

Check service health:
```bash
docker compose ps
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f beat
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| API returns 401 | Check SECRET_KEY in .env |
| Webhooks rejected | Add X-Webhook-Token header |
| Feeds not syncing | Check `docker compose logs beat` |
| Cortex jobs failing | Verify CORTEX_API_KEY in .env |
| ES connection refused | Wait 30s for ES startup |
