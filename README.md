# Neev Threat Intelligence Platform

Enterprise-grade Threat Intelligence Platform (TIP) for SOC teams, with modular ingestion, normalization, enrichment, scoring, and a React-based SOC dashboard.

## Architecture

```
                    +--------------------+
                    |  External Feeds    |
                    | OTX | Abuse.ch |   |
                    | MISP | VirusTotal  |
                    +---------+----------+
                              |
          +-------------------+-------------------+
          | Ingestion & Worker Services (Celery)   |
          | - feed adapters                         |
          | - normalization engine                  |
          | - enrichment engine                     |
          | - scoring / correlation                 |
          +-------------------+-------------------+
                              |
         +--------------------+---------------------+
         | Data Storage Layer                     |
         | Elasticsearch (IOC index)              |
         | PostgreSQL (metadata, RBAC)            |
         | Redis (cache, Celery broker)           |
         | Neo4j (optional relationship graph)     |
         +--------------------+---------------------+
                              |
         +--------------------+---------------------+
         | API Gateway / FastAPI                 |
         | - JWT auth                            |
         | - RBAC                                |
         | - search/filter                       |
         +--------------------+---------------------+
                              |
         +--------------------+---------------------+
         | Frontend SOC Dashboard (Centrak)      |
         | - IOC search / filter                  |
         | - Threat score charts                  |
         | - GeoIP map                            |
         | - Relationship graph                   |
         | - Alerts panel                         |
         +----------------------------------------+
```

## Folder Structure

- `services/api/` - FastAPI gateway + Elasticsearch/PostgreSQL connectors
- `services/worker/` - Celery workers, feed ingestion, enrichment and scoring
- `services/ui/` - React + Tailwind SOC dashboard
- `infrastructure/` - Kubernetes manifests and deployment templates
- `.github/workflows/` - CI/CD pipeline

## Tech stack

- Python 3.12, FastAPI
- Celery + Redis
- Elasticsearch
- PostgreSQL
- React + Tailwind + ECharts
- Docker + Docker Compose
- GitHub Actions CI/CD

## Run locally

1. copy environment template

```bash
cp .env.example .env
```

2. build and start all services

```bash
docker compose up --build
```

3. open services

- API: http://localhost:8000
- Dashboard: http://localhost:4173

## Production considerations

- JWT authentication and RBAC are enforced at the API layer
- Celery workers separate ingestion, enrichment, and scoring
- Elasticsearch stores normalized IOC documents for fast search
- PostgreSQL stores user, metadata, and audit logs
- Redis provides caching and task broker support
- Environment variables and secret management are required for keys

## Integration examples

- Wazuh alert enrichment: `services/api/app/integrations/wazuh.py`
- Suricata rule generation: `services/api/app/integrations/suricata.py`

## Next steps

- deploy with Kubernetes manifests in `infrastructure/k8s/`
- add TheHive / Cortex connectors for incident management
- wire Neo4j for relationship graph visualization
- add Prometheus metrics and Grafana dashboards
# Threat-Intel-Feeder
