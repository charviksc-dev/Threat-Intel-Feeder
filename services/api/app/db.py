import logging
from typing import Any

from asyncpg import create_pool, Pool
from elasticsearch import AsyncElasticsearch
from pydantic import BaseModel
from redis.asyncio import Redis, from_url

from .config import settings

logger = logging.getLogger(__name__)


class ElasticsearchIndex(BaseModel):
    name: str
    mapping: dict[str, Any]


async def create_elasticsearch_client() -> AsyncElasticsearch:
    es = AsyncElasticsearch(hosts=[str(settings.ELASTICSEARCH_HOST)])
    logger.info("Elasticsearch client initialized")
    await ensure_indicator_index(es)
    return es


async def create_postgres_pool() -> Pool:
    pool = await create_pool(dsn=settings.POSTGRES_DSN, min_size=1, max_size=5)
    logger.info("PostgreSQL pool initialized")
    return pool


async def create_redis_client() -> Redis:
    redis = from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    logger.info("Redis cache initialized")
    return redis


async def ensure_indicator_index(es: AsyncElasticsearch) -> None:
    index_name = settings.ELASTICSEARCH_INDEX
    exists = await es.indices.exists(index=index_name)
    if exists:
        return

    mapping = {
        "mappings": {
            "properties": {
                "indicator": {"type": "keyword"},
                "type": {"type": "keyword"},
                "source": {"type": "keyword"},
                "confidence_score": {"type": "float"},
                "first_seen": {"type": "date"},
                "last_seen": {"type": "date"},
                "tags": {"type": "keyword"},
                "threat_types": {"type": "keyword"},
                "context": {"type": "text"},
                "metadata": {"type": "object", "enabled": False},
                "geo": {
                    "properties": {
                        "country": {"type": "keyword"},
                        "country_code": {"type": "keyword"},
                        "region": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "latitude": {"type": "float"},
                        "longitude": {"type": "float"},
                        "isp": {"type": "keyword"},
                        "org": {"type": "keyword"},
                        "asn": {"type": "keyword"},
                    }
                },
                "relationships": {
                    "type": "nested",
                    "properties": {
                        "indicator": {"type": "keyword"},
                        "relationship": {"type": "keyword"},
                        "type": {"type": "keyword"},
                    },
                },
            }
        }
    }

    await es.indices.create(index=index_name, body=mapping)
    logger.info("Created Elasticsearch index %s", index_name)
