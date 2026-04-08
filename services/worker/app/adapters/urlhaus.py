import csv
import logging
from io import StringIO
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# URLhaus CSV feed - malware URLs
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
# URLhaus JSON API for recent payloads
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_urlhaus_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch malware URL indicators from abuse.ch URLhaus.

    URLhaus collects and shares malware distribution URLs.
    Free to use, no API key required.
    """
    if not settings.URLHAUS_ENABLED:
        logger.info("URLhaus feed is disabled")
        return []

    indicators: list[dict[str, Any]] = []

    with httpx.Client(timeout=30) as client:
        # Fetch from CSV feed
        try:
            response = client.get(URLHAUS_CSV_URL)
            response.raise_for_status()
            text = response.text
            reader = csv.reader(StringIO(text))

            for row in reader:
                if len(indicators) >= limit:
                    break
                # Skip comments and headers
                if not row or row[0].startswith("#"):
                    continue
                try:
                    # CSV format: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
                    if len(row) < 5:
                        continue
                    url_value = row[2].strip() if row[2] else ""
                    threat = row[4].strip() if row[4] else "malware"
                    tags = (
                        [t.strip() for t in row[5].split(",")]
                        if len(row) > 5 and row[5]
                        else []
                    )

                    if url_value:
                        indicators.append(
                            {
                                "indicator": url_value,
                                "type": "url",
                                "source": "urlhaus",
                                "first_seen": row[1].strip() if row[1] else None,
                                "threat_types": [threat],
                                "tags": tags,
                                "metadata": {
                                    "urlhaus_id": row[0].strip() if row[0] else None,
                                    "url_status": row[3].strip()
                                    if len(row) > 3
                                    else None,
                                    "urlhaus_link": row[6].strip()
                                    if len(row) > 6
                                    else None,
                                    "reporter": row[7].strip()
                                    if len(row) > 7
                                    else None,
                                },
                            }
                        )
                except Exception:
                    continue
        except Exception as e:
            logger.warning("Failed to fetch URLhaus CSV: %s", e)

        # Also fetch from JSON API for recent payloads
        try:
            response = client.get(URLHAUS_API_URL)
            response.raise_for_status()
            data = response.json()

            for entry in data.get("urls", []):
                if len(indicators) >= limit:
                    break
                url_value = entry.get("url", "")
                if url_value:
                    indicators.append(
                        {
                            "indicator": url_value,
                            "type": "url",
                            "source": "urlhaus",
                            "first_seen": entry.get("date_added"),
                            "threat_types": [entry.get("threat", "malware")],
                            "tags": entry.get("tags", []),
                            "metadata": {
                                "urlhaus_id": entry.get("id"),
                                "url_status": entry.get("url_status"),
                                "payloads": entry.get("payloads", []),
                            },
                        }
                    )
        except Exception as e:
            logger.warning("Failed to fetch URLhaus API: %s", e)

    logger.info("Fetched %d indicators from URLhaus", len(indicators))
    return indicators
