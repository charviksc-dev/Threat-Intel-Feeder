"""TheHive SOAR Integration

Pushes correlated alerts and IOCs to TheHive for:
- Case management
- Alert triage
- Analyst workflow
- Cortex analyzer enrichment

Supports:
1. Push alerts to TheHive
2. Create cases from correlated alerts
3. Sync IOCs as observables
4. Query TheHive for existing cases
"""

import json
import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def push_alert(
    title: str,
    description: str,
    source: str,
    source_ref: str,
    severity: int = 2,
    tags: list[str] | None = None,
    observables: list[dict[str, Any]] | None = None,
    tlp: int = 2,
) -> dict[str, Any] | None:
    """Push an alert to TheHive.

    Args:
        title: Alert title
        description: Alert description (markdown supported)
        source: Source name (e.g., "wazuh", "suricata", "neev")
        source_ref: Unique reference ID
        severity: 1=low, 2=medium, 3=high, 4=critical
        tags: List of tags
        observables: List of observables to attach
        tlp: TLP level (0=white, 1=green, 2=amber, 3=red)
    """
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        logger.debug("TheHive not configured, skipping alert push")
        return None

    alert_data = {
        "title": title,
        "description": description,
        "type": source,
        "source": source,
        "sourceRef": source_ref,
        "severity": severity,
        "tags": tags or [],
        "tlp": tlp,
        "pap": tlp,
    }

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{settings.THEHIVE_URL}/api/alert",
                json=alert_data,
                headers={
                    "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201):
                result = response.json()
                alert_id = result.get("id", "")

                # Add observables if provided
                if observables and alert_id:
                    for obs in observables:
                        _add_observable(client, alert_id, obs)

                logger.info("Pushed alert to TheHive: %s", source_ref)
                return result
            else:
                logger.warning(
                    "TheHive returned %d: %s", response.status_code, response.text
                )
                return None
    except Exception as e:
        logger.warning("Failed to push to TheHive: %s", e)
        return None


def create_case(
    title: str,
    description: str,
    severity: int = 2,
    tags: list[str] | None = None,
    tlp: int = 2,
) -> dict[str, Any] | None:
    """Create a case in TheHive from correlated alerts."""
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        return None

    case_data = {
        "title": title,
        "description": description,
        "severity": severity,
        "tags": tags or [],
        "tlp": tlp,
        "pap": tlp,
    }

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{settings.THEHIVE_URL}/api/case",
                json=case_data,
                headers={
                    "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201):
                result = response.json()
                logger.info("Created case in TheHive: %s", title)
                return result
            else:
                logger.warning("TheHive case creation failed: %d", response.status_code)
                return None
    except Exception as e:
        logger.warning("Failed to create TheHive case: %s", e)
        return None


def push_observable_to_case(
    case_id: str,
    data_type: str,
    data: str,
    message: str = "",
    tlp: int = 2,
    ioc: bool = True,
) -> bool:
    """Add an observable to an existing TheHive case.

    Args:
        case_id: TheHive case ID
        data_type: "ip", "domain", "hash", "url", "filename", etc.
        data: The observable value
        message: Description
        tlp: TLP level
        ioc: Whether this is an IOC
    """
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        return False

    obs_data = {
        "dataType": data_type,
        "data": data,
        "message": message,
        "tlp": tlp,
        "ioc": ioc,
    }

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{settings.THEHIVE_URL}/api/case/{case_id}/observable",
                json=obs_data,
                headers={
                    "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            return response.status_code in (200, 201)
    except Exception as e:
        logger.warning("Failed to push observable to TheHive: %s", e)
        return False


def _add_observable(
    client: httpx.Client, alert_id: str, observable: dict[str, Any]
) -> None:
    """Add an observable to a TheHive alert."""
    try:
        client.post(
            f"{settings.THEHIVE_URL}/api/alert/{alert_id}/observable",
            json=observable,
            headers={
                "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                "Content-Type": "application/json",
            },
        )
    except Exception:
        pass


def convert_indicator_to_observable(indicator: dict[str, Any]) -> dict[str, Any]:
    """Convert our indicator format to TheHive observable format."""
    type_map = {
        "ipv4": "ip",
        "ipv6": "ip",
        "domain": "domain",
        "url": "url",
        "hash": "hash",
        "email": "email",
    }

    ioc_type = indicator.get("type", "other")
    data_type = type_map.get(ioc_type, "other")

    return {
        "dataType": data_type,
        "data": indicator.get("indicator", ""),
        "message": f"From {indicator.get('source', 'neev')} - {', '.join(indicator.get('threat_types', []))}",
        "tlp": 2,
        "ioc": True,
        "tags": indicator.get("tags", []),
    }
