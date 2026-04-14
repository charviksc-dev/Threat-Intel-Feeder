from fastapi import APIRouter, Depends
from datetime import datetime, timezone
from .dependencies import get_postgres_pool, get_redis_client
from ..db import create_elasticsearch_client
from ..config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["health"])


async def check_postgres(pool) -> dict:
    """Check PostgreSQL connection and health."""
    try:
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT 1")
            return {
                "status": "healthy",
                "latency_ms": 0,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def check_elasticsearch() -> dict:
    """Check Elasticsearch connection and health."""
    try:
        es = create_elasticsearch_client()
        start = datetime.now(timezone.utc)
        health = await es.cluster.health()
        latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        return {
            "status": "healthy" if health.get("status") == "green" or health.get("status") == "yellow" else "unhealthy",
            "cluster_status": health.get("status"),
            "latency_ms": round(latency, 2),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Elasticsearch health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


async def check_redis(redis_client) -> dict:
    """Check Redis connection and health."""
    try:
        start = datetime.now(timezone.utc)
        await redis_client.ping()
        latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        # Check memory usage
        info = await redis_client.info("memory")
        used_memory = info.get("used_memory", 0)
        max_memory = info.get("maxmemory", 0)

        return {
            "status": "healthy",
            "latency_ms": round(latency, 2),
            "used_memory_bytes": used_memory,
            "max_memory_bytes": max_memory,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Basic health check endpoint."""
    return {"status": "ok", "service": "neev-tip-api"}


@router.get("/health/extended")
async def extended_health_check(
    pool=Depends(get_postgres_pool),
    redis_client=Depends(get_redis_client),
) -> dict:
    """Extended health check with dependency status."""
    postgres_health = await check_postgres(pool)
    es_health = await check_elasticsearch()
    redis_health = await check_redis(redis_client)

    overall_status = "healthy"
    if any(h["status"] == "unhealthy" for h in [postgres_health, es_health, redis_health]):
        overall_status = "degraded"

    return {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": {
            "postgres": postgres_health,
            "elasticsearch": es_health,
            "redis": redis_health
        }
    }
