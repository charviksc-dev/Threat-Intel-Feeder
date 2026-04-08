import json
import logging
from typing import Any

import httpx
from redis import Redis

from ..config import settings

logger = logging.getLogger(__name__)


def get_virustotal_report(indicator: str, cache: Redis) -> dict[str, Any]:
    cache_key = f"vt:{indicator}"
    cached = cache.get(cache_key)
    if cached:
        return json.loads(cached)

    if not settings.VIRUSTOTAL_API_KEY or settings.VIRUSTOTAL_API_KEY.startswith(
        "YOUR_"
    ):
        return {}

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
    }
    url = f"https://www.virustotal.com/api/v3/search?query={indicator}"

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            response = client.get(url)
            if response.status_code == 401:
                logger.debug("VT API key unauthorized, skipping enrichment")
                return {}
            if response.status_code == 429:
                logger.debug("VT rate limit hit, skipping enrichment")
                return {}
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as e:
        logger.debug("VT lookup failed for %s: %s", indicator, e)
        return {}

    results = data.get("data", [])
    report = {
        "indicator": indicator,
        "vt_total": len(results),
        "vt_score": None,
        "vt_last_analysis": None,
    }
    if results:
        attributes = results[0].get("attributes", {})
        report["vt_score"] = attributes.get("reputation")
        report["vt_last_analysis"] = attributes.get("last_analysis_date")

    cache.set(cache_key, json.dumps(report), ex=settings.CACHE_TTL_SECONDS)
    return report
