import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

OPENPHISH_FEED_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)


def fetch_openphish_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch phishing URL indicators from OpenPhish public feed.

    OpenPhish provides a regularly updated list of verified phishing URLs.
    Free to use, no API key required.
    """
    if not settings.OPENPHISH_ENABLED:
        logger.info("OpenPhish feed is disabled")
        return []

    indicators: list[dict[str, Any]] = []

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(OPENPHISH_FEED_URL)
            response.raise_for_status()
            lines = response.text.strip().splitlines()

            for line in lines:
                if len(indicators) >= limit:
                    break
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                indicators.append(
                    {
                        "indicator": url,
                        "type": "url",
                        "source": "openphish",
                        "threat_types": ["phishing"],
                        "tags": ["phishing", "openphish"],
                        "metadata": {
                            "feed": "openphish_public",
                        },
                    }
                )
    except Exception as e:
        logger.warning("Failed to fetch OpenPhish feed: %s", e)
        return []

    logger.info("Fetched %d indicators from OpenPhish", len(indicators))
    return indicators
