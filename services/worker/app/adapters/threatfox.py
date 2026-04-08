import json
import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox_indicators(days: int = 1, limit: int = 200) -> list[dict[str, Any]]:
    """Fetch IOCs from abuse.ch ThreatFox.

    ThreatFox collects and shares IOCs (Indicators of Compromise)
    associated with malware. Using the free public JSON export.
    """
    if not settings.THREATFOX_ENABLED:
        logger.info("ThreatFox feed is disabled")
        return []

    url = "https://threatfox.abuse.ch/export/json/recent/"
    indicators: list[dict[str, Any]] = []

    with httpx.Client(timeout=30) as client:
        try:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()

            type_mapping = {
                "ip:port": "ipv4",
                "domain": "domain",
                "url": "url",
                "md5_hash": "hash",
                "sha1_hash": "hash",
                "sha256_hash": "hash",
                "btc_wallet": "wallet",
            }

            for key, items in data.items():
                if len(indicators) >= limit:
                    break
                    
                for ioc in items:
                    if len(indicators) >= limit:
                        break

                    ioc_type = ioc.get("ioc_type", "")
                    ioc_value = ioc.get("ioc_value", "")
                    mapped_type = type_mapping.get(ioc_type, ioc_type)

                    if ioc_value:
                        tags = []
                        malware = ioc.get("malware_printable", "")
                        if malware:
                            tags.append(malware)
                        threat_type = ioc.get("threat_type", "")
                        if threat_type:
                            tags.append(threat_type)

                        indicators.append(
                            {
                                "indicator": ioc_value,
                                "type": mapped_type,
                                "source": "threatfox",
                                "first_seen": ioc.get("first_seen_utc"),
                                "last_seen": ioc.get("last_seen_utc"),
                                "threat_types": [threat_type] if threat_type else [],
                                "tags": tags,
                                "metadata": {
                                    "malware": malware,
                                    "malware_alias": ioc.get("malware_alias"),
                                    "confidence_level": ioc.get("confidence_level"),
                                    "reporter": ioc.get("reporter"),
                                },
                            }
                        )
        except Exception as e:
            logger.warning("Failed to fetch ThreatFox IOCs: %s", e)

    logger.info("Fetched %d indicators from ThreatFox", len(indicators))
    return indicators
