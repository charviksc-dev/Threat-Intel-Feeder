import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def fetch_otx_indicators(limit: int = 100) -> list[dict[str, Any]]:
    if not settings.OTX_API_KEY:
        logger.warning("OTX API key not configured")
        return []

    headers = {
        "X-OTX-API-KEY": settings.OTX_API_KEY,
        "Accept": "application/json",
    }
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    params = {"limit": limit}
    with httpx.Client(timeout=60, headers=headers) as client:
        response = client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

    indicators: list[dict[str, Any]] = []
    for pulse in data.get("results", []):
        for indicator in pulse.get("indicators", []):
            indicators.append(
                {
                    "indicator": indicator.get("indicator"),
                    "type": indicator.get("type"),
                    "source": "otx",
                    "first_seen": indicator.get("created"),
                    "last_seen": indicator.get("modified"),
                    "metadata": {"pulse_id": pulse.get("id"), "pulse_name": pulse.get("name")},
                }
            )
    return indicators
