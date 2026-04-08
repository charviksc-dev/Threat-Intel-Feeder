"""MISP Bidirectional Sync Integration

Pushes and pulls IOCs from MISP:

PUSH (Neev -> MISP):
- Push high-confidence IOCs to MISP as events
- Tag with Neev source information

PULL (MISP -> Neev):
- Pull IOCs from MISP events (existing adapter)
- Sync MISP attributes as indicators
- Pull tags, galaxies, taxonomies

Supports:
1. One-way sync (pull only)
2. Bidirectional sync
3. Event creation from correlated IOCs
4. Tag/taxonomy mapping
"""

import json
import logging
from datetime import datetime
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def push_indicators_to_misp(
    indicators: list[dict[str, Any]],
    event_info: str = "Neev TIP - Automated IOC Export",
    threat_level_id: int = 2,
    distribution: int = 0,
    analysis: int = 0,
) -> dict[str, Any] | None:
    """Push indicators to MISP as a new event.

    Args:
        indicators: List of indicator dicts
        event_info: Event description
        threat_level_id: 1=high, 2=medium, 3=low, 4=undefined
        distribution: 0=org, 1=community, 2=connected, 3=all
        analysis: 0=initial, 1=ongoing, 2=completed
    """
    if not settings.MISP_API_URL or not settings.MISP_API_KEY:
        logger.debug("MISP not configured, skipping push")
        return None

    # Create MISP event
    event = {
        "Event": {
            "info": event_info,
            "threat_level_id": threat_level_id,
            "distribution": distribution,
            "analysis": analysis,
            "Tag": [
                {"name": "source:neev-tip"},
                {"name": "type:automated-export"},
            ],
        },
        "Attribute": [],
    }

    # Convert indicators to MISP attributes
    type_map = {
        "ipv4": "ip-src",
        "ipv6": "ip-src",
        "domain": "domain",
        "url": "url",
        "hash": "md5",
        "email": "email-src",
    }

    for ind in indicators:
        attr_type = type_map.get(ind.get("type", ""), "text")
        value = ind.get("indicator", "")
        comment = f"Source: {ind.get('source', 'neev')}, Threat: {', '.join(ind.get('threat_types', []))}"

        event["Attribute"].append(
            {
                "type": attr_type,
                "category": "Network activity",
                "value": value,
                "comment": comment,
                "to_ids": True,
                "distribution": distribution,
                "Tag": [
                    {"name": f"source:{ind.get('source', 'neev')}"},
                    {"name": "confidence:high"},
                ],
            }
        )

    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(
                f"{settings.MISP_API_URL}/events/add",
                json=event,
                headers={
                    "Authorization": settings.MISP_API_KEY,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201):
                result = response.json()
                event_id = result.get("Event", {}).get("id")
                logger.info(
                    "Pushed %d indicators to MISP event %s", len(indicators), event_id
                )
                return result
            else:
                logger.warning(
                    "MISP push failed: %d - %s",
                    response.status_code,
                    response.text[:200],
                )
                return None
    except Exception as e:
        logger.warning("Failed to push to MISP: %s", e)
        return None


def pull_misp_events(
    tags: list[str] | None = None,
    last_days: int = 7,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Pull IOCs from MISP events.

    Args:
        tags: Filter by MISP tags (e.g., ["tlp:white"])
        last_days: Only pull events from last N days
        limit: Maximum number of events
    """
    if not settings.MISP_API_URL or not settings.MISP_API_KEY:
        return []

    indicators = []
    type_mapping = {
        "ip-src": "ipv4",
        "ip-dst": "ipv4",
        "ip-src|port": "ipv4",
        "ip-dst|port": "ipv4",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "email-src": "email",
        "email-dst": "email",
    }

    with httpx.Client(timeout=60) as client:
        try:
            payload = {
                "returnFormat": "json",
                "last": last_days,
                "limit": limit,
                "includeEventTags": True,
            }
            if tags:
                payload["tags"] = tags

            response = client.post(
                f"{settings.MISP_API_URL}/attributes/restSearch",
                json=payload,
                headers={
                    "Authorization": settings.MISP_API_KEY,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            data = response.json()

            for attr in data.get("response", {}).get("Attribute", []):
                attr_type = attr.get("type", "")
                mapped_type = type_mapping.get(attr_type, attr_type)
                value = attr.get("value", "")

                # Handle composite values (ip|port)
                if "|" in value:
                    value = value.split("|")[0]

                if value:
                    indicators.append(
                        {
                            "indicator": value,
                            "type": mapped_type,
                            "source": "misp",
                            "first_seen": attr.get("timestamp"),
                            "tags": [t.get("name", "") for t in attr.get("Tag", [])],
                            "metadata": {
                                "misp_event_id": attr.get("event_id"),
                                "misp_attribute_id": attr.get("id"),
                                "category": attr.get("category"),
                                "comment": attr.get("comment"),
                                "to_ids": attr.get("to_ids"),
                            },
                        }
                    )

        except Exception as e:
            logger.warning("Failed to pull from MISP: %s", e)

    logger.info("Pulled %d indicators from MISP", len(indicators))
    return indicators


def sync_misp_tag_taxonomy(misp_tags: list[str]) -> list[str]:
    """Map MISP tags to Neev threat types."""
    threat_types = []
    tag_mappings = {
        "malware": "malware",
        "ransomware": "ransomware",
        "botnet": "botnet-c2",
        "phishing": "phishing",
        "apt": "apt",
        "exploit": "exploit",
        "scanner": "scan",
        "bruteforce": "bruteforce",
    }

    for tag in misp_tags:
        tag_lower = tag.lower()
        for keyword, threat_type in tag_mappings.items():
            if keyword in tag_lower:
                threat_types.append(threat_type)
                break

    return threat_types or ["misp-tagged"]
