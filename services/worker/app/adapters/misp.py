import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def fetch_misp_indicators(limit: int = 100) -> list[dict[str, Any]]:
    if not settings.MISP_API_URL or not settings.MISP_API_KEY:
        logger.warning("MISP integration is not configured")
        return []

    url = f"{settings.MISP_API_URL}/attributes/restSearch"
    headers = {
        "Accept": "application/json",
        "Authorization": settings.MISP_API_KEY,
    }
    payload = {
        "returnFormat": "json",
        "includeEventTags": True,
        "limit": limit,
    }

    with httpx.Client(timeout=30, headers=headers, verify=False) as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()

    indicators: list[dict[str, Any]] = []
    for event in data.get("response", {}).get("Attribute", []):
        indicators.append(
            {
                "indicator": event.get("value"),
                "type": event.get("type"),
                "source": "misp",
                "first_seen": event.get("timestamp"),
                "metadata": {
                    "event_id": event.get("event_id"),
                    "category": event.get("category"),
                    "comment": event.get("comment"),
                },
            }
        )
    return indicators
