import asyncio
import os
import signal

from motor.motor_asyncio import AsyncIOMotorClient

from .config import settings
from .integrations.misp import fetch_misp_indicators
from .integrations.opencti import fetch_opencti_indicators


async def load_indicators(db):
    indicators = []
    indicators.extend(await fetch_opencti_indicators())
    indicators.extend(await fetch_misp_indicators())

    if not indicators:
        return 0

    for indicator in indicators:
        query = {"indicator": indicator.get("indicator"), "source": indicator.get("source")}
        update = {"$set": {**indicator}}
        await db.indicators.update_one(query, update, upsert=True)

    return len(indicators)


async def sync_loop():
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client[settings.MONGODB_DB]

    try:
        while True:
            count = await load_indicators(db)
            print(f"Collector: synced {count} indicators")
            await asyncio.sleep(settings.FEED_SYNC_INTERVAL)
    except asyncio.CancelledError:
        pass
    finally:
        client.close()


def handle_shutdown(loop):
    for task in asyncio.all_tasks(loop):
        task.cancel()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, lambda: handle_shutdown(loop))
        loop.run_until_complete(sync_loop())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
