"""Real-time Processing - Redis Streams for live alert delivery."""

import json
import asyncio
import logging
from typing import Any, Callable

import redis.asyncio as aioredis

from ..config import settings

logger = logging.getLogger(__name__)

STREAM_NAME = "neeve:alerts"
CONSUMER_GROUP = "neeve-consumers"


async def get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL)


async def publish_alert(alert: dict[str, Any]) -> str:
    """Publish an alert to Redis Stream for real-time consumption."""
    redis = await get_redis()
    try:
        message_id = await redis.xadd(
            STREAM_NAME,
            {"data": json.dumps(alert)},
            maxlen=10000,  # Keep last 10k alerts
        )
        return message_id.decode()
    finally:
        await redis.close()


async def publish_indicators(indicators: list[dict[str, Any]]) -> int:
    """Publish scored indicators to Redis Stream."""
    redis = await get_redis()
    published = 0
    try:
        for ind in indicators:
            await redis.xadd(
                "neeve:indicators",
                {
                    "data": json.dumps(
                        {
                            "indicator": ind.get("indicator"),
                            "type": ind.get("type"),
                            "source": ind.get("source"),
                            "severity": ind.get("severity"),
                            "confidence_score": ind.get("confidence_score"),
                            "threat_types": ind.get("threat_types", []),
                        }
                    )
                },
                maxlen=50000,
            )
            published += 1
    finally:
        await redis.close()
    return published


async def consume_alerts(
    consumer_name: str = "default",
    callback: Callable[[dict[str, Any]], Any] | None = None,
    block_ms: int = 5000,
):
    """Consume alerts from Redis Stream (long-running)."""
    redis = await get_redis()

    # Create consumer group if not exists
    try:
        await redis.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass  # Group already exists

    logger.info("Starting alert consumer: %s", consumer_name)

    while True:
        try:
            messages = await redis.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=consumer_name,
                streams={STREAM_NAME: ">"},
                count=10,
                block=block_ms,
            )

            for stream, msgs in messages:
                for msg_id, data in msgs:
                    alert = json.loads(data.get(b"data", b"{}"))

                    if callback:
                        await callback(alert)

                    # Acknowledge message
                    await redis.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Consumer error: %s", e)
            await asyncio.sleep(1)

    await redis.close()


async def get_recent_alerts(count: int = 50) -> list[dict[str, Any]]:
    """Get recent alerts from Redis Stream."""
    redis = await get_redis()
    try:
        messages = await redis.xrevrange(STREAM_NAME, count=count)
        alerts = []
        for msg_id, data in messages:
            alert = json.loads(data.get(b"data", b"{}"))
            alert["_stream_id"] = msg_id.decode()
            alerts.append(alert)
        return alerts
    finally:
        await redis.close()


async def get_stream_stats() -> dict[str, Any]:
    """Get Redis Stream statistics."""
    redis = await get_redis()
    try:
        info = await redis.xinfo_stream(STREAM_NAME)
        return {
            "stream": STREAM_NAME,
            "length": info.get("length", 0),
            "last_message_id": info.get("last-generated-id", "").decode()
            if info.get("last-generated-id")
            else None,
            "first_entry": info.get("first-entry"),
            "last_entry": info.get("last-entry"),
        }
    except Exception:
        return {"stream": STREAM_NAME, "length": 0}
    finally:
        await redis.close()
