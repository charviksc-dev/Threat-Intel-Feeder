import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def fetch_virustotal_indicators(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch IOCs from VirusTotal's threat intelligence feeds.

    Uses VT's /collections endpoint to get recent curated threat feeds.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured - skipping VT feed")
        return []

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    indicators: list[dict[str, Any]] = []

    # Fetch from multiple VT collection feeds
    collection_ids = [
        "apt-reports",
        "threat-actors",
        "ransomware",
        "phishing",
    ]

    with httpx.Client(timeout=30, headers=headers) as client:
        for collection_name in collection_ids:
            try:
                # Search for recent IOCs using VT search
                search_url = "https://www.virustotal.com/api/v3/search"
                params = {
                    "query": f"p:{collection_name} fs:24h+",
                    "limit": min(limit, 30),
                }
                response = client.get(search_url, params=params)
                if response.status_code == 429:
                    logger.warning("VirusTotal rate limit hit, stopping VT feed fetch")
                    break
                response.raise_for_status()
                data = response.json()

                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    indicator_value = item.get("id", "")
                    indicator_type = item.get("type", "unknown")

                    # Map VT types to our types
                    type_mapping = {
                        "file": "hash",
                        "url": "url",
                        "domain": "domain",
                        "ip_address": "ipv4",
                    }
                    mapped_type = type_mapping.get(indicator_type, indicator_type)

                    if indicator_value:
                        indicators.append(
                            {
                                "indicator": indicator_value,
                                "type": mapped_type,
                                "source": "virustotal",
                                "first_seen": attrs.get("first_submission_date"),
                                "last_seen": attrs.get("last_analysis_date"),
                                "tags": [collection_name],
                                "metadata": {
                                    "collection": collection_name,
                                    "reputation": attrs.get("reputation", 0),
                                    "last_analysis_stats": attrs.get(
                                        "last_analysis_stats", {}
                                    ),
                                },
                            }
                        )
            except Exception as e:
                logger.warning(
                    "Failed to fetch VT collection %s: %s", collection_name, e
                )
                continue

        # Also fetch from VT's passive DNS and detected URLs
        try:
            detected_url = "https://www.virustotal.com/api/v3/intelligence/search"
            params = {
                "query": "positives:5+ fs:24h+",
                "limit": min(limit, 30),
            }
            response = client.get(detected_url, params=params)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    indicator_value = item.get("id", "")
                    indicator_type = item.get("type", "unknown")
                    type_mapping = {
                        "file": "hash",
                        "url": "url",
                        "domain": "domain",
                        "ip_address": "ipv4",
                    }
                    mapped_type = type_mapping.get(indicator_type, indicator_type)
                    if indicator_value:
                        indicators.append(
                            {
                                "indicator": indicator_value,
                                "type": mapped_type,
                                "source": "virustotal",
                                "first_seen": attrs.get("first_submission_date"),
                                "last_seen": attrs.get("last_analysis_date"),
                                "tags": ["detected"],
                                "metadata": {
                                    "collection": "intelligence-search",
                                    "reputation": attrs.get("reputation", 0),
                                    "last_analysis_stats": attrs.get(
                                        "last_analysis_stats", {}
                                    ),
                                },
                            }
                        )
        except Exception as e:
            logger.warning("Failed to fetch VT intelligence search: %s", e)

    logger.info("Fetched %d indicators from VirusTotal", len(indicators))
    return indicators
