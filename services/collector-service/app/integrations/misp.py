import httpx

from .config import settings


async def fetch_misp_indicators() -> list[dict]:
    if not settings.MISP_API_URL or not settings.MISP_API_KEY:
        return []

    url = f"{settings.MISP_API_URL}/events/restSearch"
    headers = {
        "Authorization": settings.MISP_API_KEY,
        "Accept": "application/json",
    }
    payload = {
        "returnFormat": "json",
        "includeEventTags": True,
        "onlyIds": False,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()

    indicators = []
    for event in body.get("response", {}).get("Event", []):
        for attr in event.get("Attribute", []):
            indicators.append(
                {
                    "source": "misp",
                    "indicator": attr.get("value"),
                    "type": attr.get("type"),
                    "category": attr.get("category"),
                    "event_id": event.get("id"),
                    "last_seen": event.get("date"),
                }
            )
    return indicators
