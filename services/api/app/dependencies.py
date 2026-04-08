from fastapi import Request
from asyncpg import Pool
from redis.asyncio import Redis
from elasticsearch import AsyncElasticsearch


def get_postgres_pool(request: Request) -> Pool:
    return request.app.state.postgres


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_elasticsearch(request: Request) -> AsyncElasticsearch:
    return request.app.state.es
