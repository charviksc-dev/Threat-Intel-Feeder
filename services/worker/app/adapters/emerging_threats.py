import csv
import logging
from io import StringIO
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# Emerging Threats - Open ruleset with compromised IPs
ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
# ET botnet C2 list
ET_BOTNET_URL = "https://rules.emergingthreats.net/fwrules/emerging-PIX-DSX.rules"


def fetch_emerging_threats_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch compromised IP indicators from Emerging Threats.

    Emerging Threats provides open-source threat intelligence rulesets.
    The compromised-ips list contains IPs identified as compromised.
    Free to use, no API key required.
    """
    if not settings.EMERGING_THREATS_ENABLED:
        logger.info("Emerging Threats feed is disabled")
        return []

    indicators: list[dict[str, Any]] = []

    with httpx.Client(timeout=30) as client:
        # Fetch compromised IPs list
        try:
            response = client.get(ET_COMPROMISED_URL)
            response.raise_for_status()
            lines = response.text.strip().split("\n")

            for line in lines:
                if len(indicators) >= limit:
                    break
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Extract IP (format is just IP per line)
                ip_value = line.split()[0] if line else ""
                if ip_value and "." in ip_value:
                    indicators.append(
                        {
                            "indicator": ip_value,
                            "type": "ipv4",
                            "source": "emerging-threats",
                            "threat_types": ["compromised"],
                            "tags": ["compromised-host"],
                            "metadata": {
                                "list": "compromised-ips",
                                "source_url": ET_COMPROMISED_URL,
                            },
                        }
                    )
            logger.info("Fetched %d indicators from Emerging Threats", len(indicators))
        except Exception as e:
            logger.warning("Failed to fetch Emerging Threats compromised IPs: %s", e)

    return indicators
