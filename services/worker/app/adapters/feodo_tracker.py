import csv
import logging
from io import StringIO
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# Feodo Tracker - Botnet C2 IP blocklist
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
# Feodo Tracker JSON feed
FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch_feodo_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch botnet C2 IP indicators from Feodo Tracker.

    Feodo Tracker tracks botnet C2 servers used by banking trojans
    like Dridex, TrickBot, QakBot, etc. Free to use, no API key.
    """
    if not settings.FEODO_TRACKER_ENABLED:
        logger.info("Feodo Tracker feed is disabled")
        return []

    indicators: list[dict[str, Any]] = []

    with httpx.Client(timeout=30) as client:
        # Try JSON feed first (richer data)
        try:
            response = client.get(FEODO_JSON_URL)
            response.raise_for_status()
            data = response.json()

            for entry in data:
                if len(indicators) >= limit:
                    break

                ip_value = entry.get("ip_address", "")
                if not ip_value:
                    continue

                malware_family = entry.get("malware", "")
                tags = []
                if malware_family:
                    tags.append(malware_family)

                indicators.append(
                    {
                        "indicator": ip_value,
                        "type": "ipv4",
                        "source": "feodo-tracker",
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "threat_types": ["botnet-c2"],
                        "tags": tags,
                        "metadata": {
                            "port": entry.get("port"),
                            "status": entry.get("status"),
                            "hostname": entry.get("hostname"),
                            "malware_family": malware_family,
                            "asn": entry.get("as_number"),
                            "as_name": entry.get("as_name"),
                            "country": entry.get("country"),
                        },
                    }
                )
            logger.info(
                "Fetched %d indicators from Feodo Tracker (JSON)", len(indicators)
            )
        except Exception as e:
            logger.warning(
                "Failed to fetch Feodo JSON feed, falling back to CSV: %s", e
            )

            # Fallback to CSV blocklist
            try:
                response = client.get(FEODO_BLOCKLIST_URL)
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
                        # CSV format: first_seen, dst_ip, dst_port, c2_status, last_online, hostname, malware
                        if len(row) < 2:
                            continue
                        ip_value = row[1].strip()
                        malware_family = row[6].strip() if len(row) > 6 else ""

                        if ip_value:
                            tags = [malware_family] if malware_family else []
                            indicators.append(
                                {
                                    "indicator": ip_value,
                                    "type": "ipv4",
                                    "source": "feodo-tracker",
                                    "first_seen": row[0].strip() if row[0] else None,
                                    "threat_types": ["botnet-c2"],
                                    "tags": tags,
                                    "metadata": {
                                        "port": row[2].strip()
                                        if len(row) > 2
                                        else None,
                                        "status": row[3].strip()
                                        if len(row) > 3
                                        else None,
                                        "last_online": row[4].strip()
                                        if len(row) > 4
                                        else None,
                                        "hostname": row[5].strip()
                                        if len(row) > 5
                                        else None,
                                        "malware_family": malware_family,
                                    },
                                }
                            )
                    except Exception:
                        continue
                logger.info(
                    "Fetched %d indicators from Feodo Tracker (CSV)", len(indicators)
                )
            except Exception as e2:
                logger.warning("Failed to fetch Feodo CSV feed: %s", e2)

    return indicators
