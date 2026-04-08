import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"


def fetch_greynoise_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch IP enrichment data from GreyNoise Community API.

    GreyNoise identifies internet scanners and background noise IPs.
    Requires a GreyNoise API key configured in settings.
    """
    if not settings.GREYNOISE_API_KEY:
        logger.warning("GreyNoise API key not configured - skipping GreyNoise feed")
        return []

    headers = {
        "key": settings.GREYNOISE_API_KEY,
        "Accept": "application/json",
    }

    indicators: list[dict[str, Any]] = []

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            # Fetch recently observed IPs from GreyNoise RIOT and community endpoints
            # Use the quick check endpoint to get a list of noisy IPs
            riot_url = "https://api.greynoise.io/v3/experimental/noise/quick"
            response = client.get(riot_url)
            response.raise_for_status()
            data = response.json()

            for entry in data.get("data", []):
                if len(indicators) >= limit:
                    break
                ip = entry.get("ip", "")
                if not ip:
                    continue

                # Enrich each IP with community data
                try:
                    community_url = GREYNOISE_COMMUNITY_URL.format(ip=ip)
                    detail_resp = client.get(community_url)
                    if detail_resp.status_code == 200:
                        detail = detail_resp.json()
                    else:
                        detail = entry
                except Exception:
                    detail = entry

                tags = detail.get("tags", []) or []
                classification = detail.get("classification", "unknown")
                name = detail.get("name", "")
                noise = detail.get("noise", False)
                riot = detail.get("riot", False)

                threat_types = []
                if classification == "malicious":
                    threat_types.append("malicious")
                elif classification == "suspicious":
                    threat_types.append("suspicious")
                else:
                    threat_types.append("scanner")

                indicators.append(
                    {
                        "indicator": ip,
                        "type": "ipv4",
                        "source": "greynoise",
                        "threat_types": threat_types,
                        "tags": ["greynoise", classification] + tags,
                        "metadata": {
                            "classification": classification,
                            "name": name,
                            "noise": noise,
                            "riot": riot,
                            "link": detail.get("link", ""),
                            "last_seen": detail.get("last_seen", ""),
                        },
                    }
                )
    except Exception as e:
        logger.warning("Failed to fetch GreyNoise data: %s", e)
        return []

    logger.info("Fetched %d indicators from GreyNoise", len(indicators))
    return indicators


def enrich_greynoise_ip(ip: str) -> dict[str, Any]:
    """Enrich a single IP address using GreyNoise Community API.

    Returns enrichment data or empty dict if the IP is not found or on error.
    """
    if not settings.GREYNOISE_API_KEY:
        logger.warning("GreyNoise API key not configured")
        return {}

    headers = {
        "key": settings.GREYNOISE_API_KEY,
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            url = GREYNOISE_COMMUNITY_URL.format(ip=ip)
            response = client.get(url)
            if response.status_code == 404:
                return {"ip": ip, "found": False, "source": "greynoise"}
            response.raise_for_status()
            data = response.json()
            return {
                "ip": ip,
                "found": True,
                "source": "greynoise",
                "classification": data.get("classification", ""),
                "name": data.get("name", ""),
                "tags": data.get("tags", []),
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "link": data.get("link", ""),
                "last_seen": data.get("last_seen", ""),
            }
    except Exception as e:
        logger.warning("Failed to enrich IP %s via GreyNoise: %s", ip, e)
        return {}
