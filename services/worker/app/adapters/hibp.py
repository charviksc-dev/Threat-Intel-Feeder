import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_BREACHED_ACCOUNT_URL = f"{HIBP_API_BASE}/breachedaccount/{{email}}"


def fetch_hibp_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch breach indicators from Have I Been Pwned.

    HIBP aggregates data breach information for email addresses.
    Requires an HIBP API key configured in settings.
    """
    if not settings.HIBP_API_KEY:
        logger.warning("HIBP API key not configured - skipping HIBP feed")
        return []

    if not settings.HIBP_MONITORED_EMAILS:
        logger.info("No emails configured for HIBP monitoring")
        return []

    headers = {
        "hibp-api-key": settings.HIBP_API_KEY,
        "User-Agent": "ThreatIntelFeedIntegrator",
        "Accept": "application/json",
    }

    indicators: list[dict[str, Any]] = []

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            for email in settings.HIBP_MONITORED_EMAILS:
                if len(indicators) >= limit:
                    break
                try:
                    url = HIBP_BREACHED_ACCOUNT_URL.format(email=email)
                    response = client.get(url)

                    if response.status_code == 404:
                        logger.debug("No breaches found for %s", email)
                        continue

                    if response.status_code == 429:
                        logger.warning("HIBP rate limit hit, stopping")
                        break

                    response.raise_for_status()
                    breaches = response.json()

                    for breach in breaches:
                        if len(indicators) >= limit:
                            break
                        breach_name = breach.get("Name", "")
                        domain = breach.get("Domain", "")
                        breach_date = breach.get("BreachDate", "")
                        data_classes = breach.get("DataClasses", [])
                        is_verified = breach.get("IsVerified", False)
                        pwn_count = breach.get("PwnCount", 0)

                        indicators.append(
                            {
                                "indicator": email,
                                "type": "email",
                                "source": "hibp",
                                "threat_types": ["breached"],
                                "tags": [
                                    "hibp",
                                    "breach",
                                    breach_name.lower().replace(" ", "_"),
                                ],
                                "metadata": {
                                    "breach_name": breach_name,
                                    "breach_domain": domain,
                                    "breach_date": breach_date,
                                    "data_classes": data_classes,
                                    "is_verified": is_verified,
                                    "pwn_count": pwn_count,
                                    "description": breach.get("Description", ""),
                                },
                            }
                        )

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        logger.warning("HIBP rate limit hit for %s", email)
                        break
                    logger.warning("HIBP API error for %s: %s", email, e)
                    continue
                except Exception as e:
                    logger.warning("Failed to check HIBP for %s: %s", email, e)
                    continue
    except Exception as e:
        logger.warning("Failed to fetch HIBP data: %s", e)
        return []

    logger.info("Fetched %d indicators from HIBP", len(indicators))
    return indicators


def check_email_breaches(email: str) -> list[dict[str, Any]]:
    """Check a single email address against HIBP for breaches.

    Returns a list of breach records or empty list if none found or on error.
    """
    if not settings.HIBP_API_KEY:
        logger.warning("HIBP API key not configured")
        return []

    headers = {
        "hibp-api-key": settings.HIBP_API_KEY,
        "User-Agent": "ThreatIntelFeedIntegrator",
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            url = HIBP_BREACHED_ACCOUNT_URL.format(email=email)
            response = client.get(url)

            if response.status_code == 404:
                return []

            response.raise_for_status()
            return response.json()
    except Exception as e:
        logger.warning("Failed to check HIBP for %s: %s", email, e)
        return []
