import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"


def _parse_spamhaus_text(text: str, list_name: str) -> list[dict[str, str]]:
    """Parse Spamhaus DROP/EDROP text format.

    Format: CIDR ; SBL ID ; date
    Lines starting with ; are comments.
    """
    entries = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = [p.strip() for p in line.split(";")]
        if not parts:
            continue
        cidr = parts[0]
        sbl_id = parts[1] if len(parts) > 1 else ""
        date_str = parts[2] if len(parts) > 2 else ""
        entries.append(
            {
                "cidr": cidr,
                "sbl_id": sbl_id,
                "date": date_str,
                "list_name": list_name,
            }
        )
    return entries


def fetch_spamhaus_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch IP blocklist indicators from Spamhaus DROP and EDROP.

    DROP (Don't Route Or Peer) lists hijacked netblocks and netblocks
    used entirely by criminals. EDROP is an extension of DROP.
    Free to use, no API key required.
    """
    if not settings.SPAMHAUS_ENABLED:
        logger.info("Spamhaus feed is disabled")
        return []

    indicators: list[dict[str, Any]] = []

    with httpx.Client(timeout=30) as client:
        # Fetch DROP list
        try:
            response = client.get(SPAMHAUS_DROP_URL)
            response.raise_for_status()
            entries = _parse_spamhaus_text(response.text, "drop")
            for entry in entries:
                if len(indicators) >= limit:
                    break
                indicators.append(
                    {
                        "indicator": entry["cidr"],
                        "type": "cidr",
                        "source": "spamhaus",
                        "threat_types": ["blocklist"],
                        "tags": ["spamhaus", "drop", "blocklist"],
                        "metadata": {
                            "list_name": entry["list_name"],
                            "sbl_id": entry["sbl_id"],
                            "date": entry["date"],
                        },
                    }
                )
        except Exception as e:
            logger.warning("Failed to fetch Spamhaus DROP list: %s", e)

        # Fetch EDROP list
        try:
            response = client.get(SPAMHAUS_EDROP_URL)
            response.raise_for_status()
            entries = _parse_spamhaus_text(response.text, "edrop")
            for entry in entries:
                if len(indicators) >= limit:
                    break
                indicators.append(
                    {
                        "indicator": entry["cidr"],
                        "type": "cidr",
                        "source": "spamhaus",
                        "threat_types": ["blocklist"],
                        "tags": ["spamhaus", "edrop", "blocklist"],
                        "metadata": {
                            "list_name": entry["list_name"],
                            "sbl_id": entry["sbl_id"],
                            "date": entry["date"],
                        },
                    }
                )
        except Exception as e:
            logger.warning("Failed to fetch Spamhaus EDROP list: %s", e)

    logger.info("Fetched %d indicators from Spamhaus", len(indicators))
    return indicators
