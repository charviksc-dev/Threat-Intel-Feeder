import httpx

from .config import settings


async def fetch_opencti_indicators() -> list[dict]:
    if not settings.OPENCTI_API_URL or not settings.OPENCTI_API_TOKEN:
        return []

    headers = {
        "Authorization": f"Bearer {settings.OPENCTI_API_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "query": "{ indicators(first: 50) { edges { node { id name description pattern created } } } }"
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(settings.OPENCTI_API_URL, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()

    indicators = []
    for edge in body.get("data", {}).get("indicators", {}).get("edges", []):
        node = edge.get("node") or {}
        if node:
            indicators.append(
                {
                    "source": "opencti",
                    "indicator": node.get("name") or node.get("id"),
                    "description": node.get("description"),
                    "pattern": node.get("pattern"),
                    "last_seen": node.get("created"),
                }
            )
    return indicators
