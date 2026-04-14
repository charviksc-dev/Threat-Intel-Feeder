# Deployment Guide for Neev Threat Intelligence Platform

## Overview

This guide covers deploying the Neev Threat Intelligence Platform to production using Docker Compose or Kubernetes.

---

## Prerequisites

- Docker and Docker Compose installed
- Docker Hub account (for registry)
- GitHub account with repository access
- SSL certificates (for HTTPS in production)

---

## CI/CD Setup

### 1. Configure GitHub Secrets

Navigate to your GitHub repository → Settings → Secrets and variables → Actions → New repository secret

Add the following secrets:

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `DOCKER_USERNAME` | Docker Hub username | `neevtip` |
| `DOCKER_PASSWORD` | Docker Hub access token | `dckr_pat_...` |

### 2. Create Docker Hub Access Token

1. Go to Docker Hub → Account Settings → Security → New Access Token
2. Create a token with "Read, Write, Delete" permissions
3. Copy the token and add it as `DOCKER_PASSWORD` secret in GitHub

---

## Deployment Methods

### Option 1: Docker Compose (Production)

#### 1. Prepare Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set production values:

```bash
# Application
APP_ENV=production
SECRET_KEY=<generate-strong-secret-key>
ALLOWED_ORIGINS=https://your-domain.com
FRONTEND_URL=https://your-domain.com

# Database
POSTGRES_USER=neev
POSTGRES_PASSWORD=<strong-postgres-password>
POSTGRES_DB=neev
POSTGRES_DSN=postgresql://neev:<strong-postgres-password>@postgres:5432/neev

# Redis
REDIS_URL=redis://redis:6379/0

# Elasticsearch
ELASTICSEARCH_HOST=http://elasticsearch:9200
ELASTICSEARCH_INDEX=neev-indicators
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=<strong-es-password>

# Docker Registry (for pulling images)
DOCKER_USERNAME=neevtip
DOCKER_REGISTRY=docker.io
```

#### 2. Pull Pre-built Images

After CI/CD pipeline completes, pull the latest images:

```bash
docker compose -f docker-compose.prod.yml pull
```

#### 3. Deploy

```bash
docker compose -f docker-compose.prod.yml up -d
```

#### 4. Verify Deployment

```bash
# Check all services are running
docker compose -f docker-compose.prod.yml ps

# Check logs
docker compose -f docker-compose.prod.yml logs -f api

# Test health endpoint
curl http://localhost:8000/api/v1/health
```

---

### Option 2: Kubernetes Deployment

#### 1. Update K8s Manifests

Edit the manifests in `infrastructure/k8s/` to use your Docker Hub images:

```yaml
# api-deployment.yaml
spec:
  containers:
  - name: api
    image: neevtip/neev-tip-api:latest
```

#### 2. Configure Secrets

```bash
kubectl create secret generic neev-secrets \
  --from-literal=postgres-password=<password> \
  --from-literal=secret-key=<secret> \
  --from-literal=elastic-password=<password>
```

#### 3. Deploy

```bash
kubectl apply -f infrastructure/k8s/secrets.yaml
kubectl apply -f infrastructure/k8s/postgres-statefulset.yaml
kubectl apply -f infrastructure/k8s/redis-deployment.yaml
kubectl apply -f infrastructure/k8s/elasticsearch-deployment.yaml
kubectl apply -f infrastructure/k8s/api-deployment.yaml
kubectl apply -f infrastructure/k8s/worker-deployment.yaml
kubectl apply -f infrastructure/k8s/ui-deployment.yaml
```

#### 4. Verify

```bash
kubectl get pods
kubectl logs -f deployment/neev-api
```

---

## SSL/TLS Configuration

### Using Nginx Reverse Proxy

1. Obtain SSL certificates (Let's Encrypt recommended)

```bash
# Using certbot
sudo certbot certonly --standalone -d your-domain.com
```

2. Place certificates in `infrastructure/nginx/certs/`:

```
infrastructure/nginx/certs/
├── fullchain.pem
└── privkey.pem
```

3. Update `infrastructure/nginx/nginx.conf` to use SSL:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        proxy_pass http://neev-ui:80;
    }

    location /api/ {
        proxy_pass http://neev-api:8000;
    }
}
```

---

## Database Initialization

### PostgreSQL

The API automatically initializes database tables on startup. To verify:

```bash
docker exec -it neev-postgres psql -U neev -d neev -c "\dt"
```

### Elasticsearch

The API automatically creates the indicator index. To verify:

```bash
curl -u elastic:<password> http://localhost:9200/_cat/indices?v
```

---

## Monitoring

### Prometheus Metrics

Metrics are available at `/metrics` endpoint:

```bash
curl http://localhost:8000/metrics
```

### Health Checks

- Basic health: `GET /api/v1/health`
- Extended health: `GET /api/v1/health/extended`

### Logs

View logs for all services:

```bash
docker compose -f docker-compose.prod.yml logs -f
```

View logs for specific service:

```bash
docker compose -f docker-compose.prod.yml logs -f api
```

---

## Backup Strategy

Follow the backup strategy documented in `BACKUP_STRATEGY.md`.

Quick setup:

```bash
# Create backup directory
mkdir -p /backups/{postgres,elasticsearch,redis}

# Add cron jobs for automated backups
crontab -e
```

---

## Scaling

### Horizontal Scaling with Docker Compose

```bash
# Scale API instances
docker compose -f docker-compose.prod.yml up -d --scale api=3

# Scale Worker instances
docker compose -f docker-compose.prod.yml up -d --scale worker=2
```

### Horizontal Pod Autoscaler (Kubernetes)

Add HPA to deployment manifests:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: neev-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: neev-api
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

---

## Troubleshooting

### Elasticsearch Authentication Issues

If you see authentication errors after enabling security:

```bash
# Reset Elasticsearch password
docker exec -it neev-elasticsearch bin/elasticsearch-reset-password -u elastic

# Update .env with new password
```

### Database Connection Issues

```bash
# Check PostgreSQL is healthy
docker exec neev-postgres pg_isready -U neev

# Check logs
docker logs neev-postgres
```

### Worker Not Processing Tasks

```bash
# Check Celery worker status
docker exec neev-worker celery -A app.celery_app.celery inspect active

# Check Celery beat is running
docker logs neev-beat
```

---

## Security Checklist

- [ ] Change all default passwords
- [ ] Enable Elasticsearch security
- [ ] Configure SSL/TLS certificates
- [ ] Set up firewall rules
- [ ] Enable rate limiting
- [ ] Configure audit logging
- [ ] Set up automated backups
- [ ] Enable Prometheus monitoring
- [ ] Review and restrict CORS origins
- [ ] Configure webhook authentication

---

## Rollback Procedure

### Docker Compose

```bash
# Pull previous version
docker compose -f docker-compose.prod.yml pull neevtip/neev-tip-api:previous-tag

# Update docker-compose.prod.yml to use previous tag
# Then restart
docker compose -f docker-compose.prod.yml up -d
```

### Kubernetes

```bash
# Rollback to previous revision
kubectl rollout undo deployment/neev-api

# Or rollback to specific revision
kubectl rollout undo deployment/neev-api --to-revision=2
```

---

## Support

For issues or questions:
- Check logs: `docker compose logs`
- Review documentation: `README.md`, `BACKUP_STRATEGY.md`
- Open an issue on GitHub
