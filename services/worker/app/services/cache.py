from redis import Redis

from ..config import settings


def create_cache_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)
