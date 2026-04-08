import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

HYBRID_ANALYSIS_API_URL = "https://www.hybrid-analysis.com/api/v2"
HYBRID_ANALYSIS_SEARCH_URL = f"{HYBRID_ANALYSIS_API_URL}/search/terms"
HYBRID_ANALYSIS_OVERVIEW_URL = f"{HYBRID_ANALYSIS_API_URL}/overview/{{id}}"


def fetch_hybrid_analysis_indicators(limit: int = 200) -> list[dict[str, Any]]:
    """Fetch malware sandbox IOCs from Hybrid Analysis.

    Hybrid Analysis is a free malware analysis service by CrowdStrike.
    Requires an API key configured in settings.
    """
    if not settings.HYBRID_ANALYSIS_API_KEY:
        logger.warning(
            "Hybrid Analysis API key not configured - skipping Hybrid Analysis feed"
        )
        return []

    headers = {
        "api-key": settings.HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "ThreatIntelFeedIntegrator",
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    indicators: list[dict[str, Any]] = []

    try:
        with httpx.Client(timeout=30, headers=headers) as client:
            # Search for recent sandbox submissions with IOCs
            search_terms = [
                {"field": "verdict", "value": "malicious"},
                {"field": "threat_score", "value": ">=70"},
            ]

            for term in search_terms:
                if len(indicators) >= limit:
                    break
                try:
                    response = client.post(
                        HYBRID_ANALYSIS_SEARCH_URL,
                        data={
                            "search_term[field]": term["field"],
                            "search_term[value]": term["value"],
                        },
                    )
                    response.raise_for_status()
                    data = response.json()

                    for result in data.get("result", []):
                        if len(indicators) >= limit:
                            break

                        sha256 = result.get("sha256", "")
                        md5 = result.get("md5", "")
                        threat_score = result.get("threat_score", 0)
                        verdict = result.get("verdict", "")
                        environment = result.get("environment_description", "")
                        submit_name = result.get("submit_name", "")
                        av_detect = result.get("av_detect", "")
                        vx_family = result.get("vx_family", "")
                        analysis_start = result.get("analysis_start_time", "")

                        if sha256:
                            indicators.append(
                                {
                                    "indicator": sha256,
                                    "type": "hash",
                                    "source": "hybrid_analysis",
                                    "threat_types": ["malware"],
                                    "tags": [
                                        "hybrid_analysis",
                                        "malware",
                                        verdict,
                                        environment,
                                    ],
                                    "metadata": {
                                        "sha256": sha256,
                                        "md5": md5,
                                        "threat_score": threat_score,
                                        "verdict": verdict,
                                        "environment": environment,
                                        "filename": submit_name,
                                        "av_detect": av_detect,
                                        "vx_family": vx_family,
                                        "analysis_time": analysis_start,
                                        "type": result.get("type", ""),
                                        "size": result.get("size", 0),
                                        "compromised": result.get("compromised", False),
                                    },
                                }
                            )

                except Exception as e:
                    logger.warning(
                        "Failed to fetch Hybrid Analysis search (%s): %s",
                        term["field"],
                        e,
                    )
                    continue

            # Also search for recent IOCs via the feeds endpoint
            try:
                feeds_url = f"{HYBRID_ANALYSIS_API_URL}/feed/latest"
                response = client.get(feeds_url)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data.get("data", []):
                        if len(indicators) >= limit:
                            break
                        ioc_type = entry.get("type", "")
                        ioc_value = entry.get("value", "")
                        if not ioc_value:
                            continue

                        type_mapping = {
                            "domain": "domain",
                            "host": "ipv4",
                            "url": "url",
                            "hash": "hash",
                            "email": "email",
                        }
                        mapped_type = type_mapping.get(ioc_type, ioc_type)

                        indicators.append(
                            {
                                "indicator": ioc_value,
                                "type": mapped_type,
                                "source": "hybrid_analysis",
                                "threat_types": ["malware"],
                                "tags": ["hybrid_analysis", "ioc_feed"],
                                "metadata": {
                                    "ioc_type": ioc_type,
                                    "associated_threat": entry.get("threat", ""),
                                },
                            }
                        )
            except Exception as e:
                logger.warning("Failed to fetch Hybrid Analysis feed: %s", e)

    except Exception as e:
        logger.warning("Failed to fetch Hybrid Analysis data: %s", e)
        return []

    logger.info("Fetched %d indicators from Hybrid Analysis", len(indicators))
    return indicators
