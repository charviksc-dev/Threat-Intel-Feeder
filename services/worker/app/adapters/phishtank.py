import csv
import logging
from io import StringIO
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

PHISHTANK_CSV_URL = "http://data.phishtank.com/data/online-valid.csv"


def fetch_phishtank_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch verified phishing URL indicators from PhishTank.

    PhishTank is a community-driven phishing verification system.
    Free to use, no API key required for the CSV feed.
    """
    if not settings.PHISHTANK_ENABLED:
        logger.info("PhishTank feed is disabled")
        return []

    indicators: list[dict[str, Any]] = []

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(PHISHTANK_CSV_URL)
            response.raise_for_status()
            reader = csv.DictReader(StringIO(response.text))

            for row in reader:
                if len(indicators) >= limit:
                    break
                try:
                    url_value = row.get("url", "").strip()
                    if not url_value:
                        continue

                    phish_id = row.get("phish_id", "").strip()
                    verified = row.get("verified", "").strip().lower() == "yes"
                    verification_time = row.get("verification_time", "").strip()
                    target = row.get("target", "").strip()

                    indicators.append(
                        {
                            "indicator": url_value,
                            "type": "url",
                            "source": "phishtank",
                            "threat_types": ["phishing"],
                            "tags": ["phishing", "verified"]
                            if verified
                            else ["phishing"],
                            "metadata": {
                                "phish_id": phish_id,
                                "verified": verified,
                                "verification_time": verification_time,
                                "target": target,
                            },
                        }
                    )
                except Exception:
                    continue
    except Exception as e:
        logger.warning("Failed to fetch PhishTank feed: %s", e)
        return []

    logger.info("Fetched %d indicators from PhishTank", len(indicators))
    return indicators
