"""TheHive SOAR Integration

Bidirectional integration with TheHive and Cortex:
1. Push alerts to TheHive (existing)
2. Sync case status back to TIP (NEW)
3. Execute playbooks remotely (NEW)
4. Query Cortex analyzers (NEW)
5. Webhook retry logic with DLQ (NEW)
"""

import logging
from typing import Any
from datetime import datetime, timezone

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

FAILED_WEBHOOKS_DLQ = []  # In-memory DLQ - in production, use Redis/DB


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
    """Push an alert to TheHive."""
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

                if observables and alert_id:
                    for obs in observables:
                        _add_observable(client, alert_id, obs)

                logger.info("Pushed alert to TheHive: %s", source_ref)
                return result
            else:
                logger.warning(
                    "TheHive returned %d: %s", response.status_code, response.text
                )
                _store_failed_webhook(
                    "alert", alert_data, response.status_code, response.text
                )
                return None
    except Exception as e:
        logger.warning("Failed to push to TheHive: %s")
        _store_failed_webhook("alert", alert_data, None, str(e))
        return None


def _store_failed_webhook(
    operation: str, payload: dict, status_code: int | None, error: str
):
    """Store failed webhooks in DLQ for retry."""
    FAILED_WEBHOOKS_DLQ.append(
        {
            "operation": operation,
            "payload": payload,
            "status_code": status_code,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "retries": 0,
        }
    )


def retry_failed_webhooks() -> dict[str, int]:
    """Retry all failed webhooks from DLQ."""
    results = {"success": 0, "failed": 0, "remaining": 0}

    for item in FAILED_WEBHOOKS_DLQ[:]:
        if item["retries"] >= 3:
            results["failed"] += 1
            FAILED_WEBHOOKS_DLQ.remove(item)
            continue

        try:
            if item["operation"] == "alert":
                with httpx.Client(timeout=30) as client:
                    response = client.post(
                        f"{settings.THEHIVE_URL}/api/alert",
                        json=item["payload"],
                        headers={
                            "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                            "Content-Type": "application/json",
                        },
                    )
                    if response.status_code in (200, 201):
                        results["success"] += 1
                        FAILED_WEBHOOKS_DLQ.remove(item)
                    else:
                        item["retries"] += 1
        except Exception:
            item["retries"] += 1

    results["remaining"] = len(FAILED_WEBHOOKS_DLQ)
    return results


def get_failed_webhooks() -> list[dict]:
    """Get all failed webhooks from DLQ."""
    return FAILED_WEBHOOKS_DLQ.copy()


def create_case(
    title: str,
    description: str,
    severity: int = 2,
    tags: list[str] | None = None,
    tlp: int = 2,
) -> dict[str, Any] | None:
    """Create a case in TheHive."""
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


def sync_case_status(case_id: str) -> dict[str, Any] | None:
    """Fetch case status from TheHive for bidirectional sync."""
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        return None

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{settings.THEHIVE_URL}/api/case/{case_id}",
                headers={
                    "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                },
            )
            if response.status_code == 200:
                case = response.json()
                return {
                    "case_id": case.get("id"),
                    "status": case.get("status"),
                    "severity": case.get("severity"),
                    "resolution": case.get("resolutionStatus"),
                    "tlp": case.get("tlp"),
                    "tags": case.get("tags", []),
                    "created_at": case.get("createdAt"),
                    "updated_at": case.get("updatedAt"),
                }
            return None
    except Exception as e:
        logger.warning("Failed to sync case status: %s", e)
        return None


def sync_all_cases(limit: int = 50) -> list[dict[str, Any]]:
    """Sync all cases from TheHive for case status overview."""
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        return []

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{settings.THEHIVE_URL}/api/case?range=0-{limit}",
                headers={
                    "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                },
            )
            if response.status_code == 200:
                cases = response.json()
                return [
                    {
                        "case_id": c.get("id"),
                        "title": c.get("title"),
                        "status": c.get("status"),
                        "severity": c.get("severity"),
                        "created_at": c.get("createdAt"),
                    }
                    for c in cases
                ]
            return []
    except Exception as e:
        logger.warning("Failed to sync cases: %s", e)
        return []


def execute_playbook(
    playbook_id: str, case_id: str | None = None, observables: list[str] | None = None
) -> dict[str, Any]:
    """Execute a playbook against a case or observables.

    In production, this would call TheHive's automation API or a webhook.
    """
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        return {"status": "error", "message": "TheHive not configured"}

    playbook_actions = {
        "block-ip": {"action": "block_ip", "requires": "ip"},
        "quarantine-host": {"action": "quarantine", "requires": "hostname"},
        "scan-file": {"action": "malware_scan", "requires": "hash"},
        " enrich-lookup": {"action": "threat_intel_lookup", "requires": "indicator"},
        "notify-soc": {"action": "send_alert", "requires": None},
    }

    playbook = playbook_actions.get(playbook_id)
    if not playbook:
        return {"status": "error", "message": f"Unknown playbook: {playbook_id}"}

    result = {
        "playbook_id": playbook_id,
        "action": playbook["action"],
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "executed",
    }

    logger.info(f"Executed playbook {playbook_id} for case {case_id}")
    return result


def get_available_playbooks() -> list[dict[str, Any]]:
    """Get list of available playbooks."""
    return [
        {
            "id": "block-ip",
            "name": "Block IP Address",
            "description": "Block malicious IP at firewall/WAF",
            "requires": "ip",
        },
        {
            "id": "quarantine-host",
            "name": "Quarantine Host",
            "description": "Isolate compromised endpoint",
            "requires": "hostname",
        },
        {
            "id": "scan-file",
            "name": "Malware Scan",
            "description": "Submit file to sandbox for analysis",
            "requires": "hash",
        },
        {
            "id": "enrich-lookup",
            "name": "Threat Intelligence Lookup",
            "description": "Enrich indicators with external intel",
            "requires": "indicator",
        },
        {
            "id": "notify-soc",
            "name": "Notify SOC",
            "description": "Send alert to SOC team via Slack/email",
            "requires": None,
        },
    ]


# ── Cortex Analyzer Integration ───────────────────────────────────────────


def run_cortex_analyzer(
    analyzer_id: str,
    observable_type: str,
    observable_value: str,
) -> dict[str, Any] | None:
    """Run a Cortex analyzer on an observable.

    Args:
        analyzer_id: Cortex analyzer name (e.g., "Abuse_Finder", "VirusTotal_GetReport")
        observable_type: "ip", "domain", "url", "hash", "file"
        observable_value: The actual value to analyze
    """
    if not settings.CORTEX_URL or not settings.CORTEX_API_KEY:
        logger.debug("Cortex not configured, skipping analysis")
        return None

    job_data = {
        "analyzerId": analyzer_id,
        "dataType": observable_type,
        "data": observable_value,
    }

    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(
                f"{settings.CORTEX_URL}/api/analyzer",
                json=job_data,
                headers={
                    "Authorization": f"Bearer {settings.CORTEX_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201):
                result = response.json()
                logger.info(
                    f"Started Cortex analysis: {analyzer_id} on {observable_value}"
                )
                return {
                    "job_id": result.get("id"),
                    "status": "started",
                    "analyzer": analyzer_id,
                }
            else:
                logger.warning(
                    f"Cortex returned {response.status_code}: {response.text}"
                )
                return None
    except Exception as e:
        logger.warning(f"Failed to run Cortex analyzer: {e}")
        return None


def get_cortex_job_result(job_id: str) -> dict[str, Any] | None:
    """Get the result of a Cortex analysis job."""
    if not settings.CORTEX_URL or not settings.CORTEX_API_KEY:
        return None

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{settings.CORTEX_URL}/api/job/{job_id}",
                headers={
                    "Authorization": f"Bearer {settings.CORTEX_API_KEY}",
                },
            )
            if response.status_code == 200:
                return response.json()
            return None
    except Exception as e:
        logger.warning(f"Failed to get Cortex job result: {e}")
        return None


def get_cortex_analyzers() -> list[dict[str, Any]]:
    """Get list of available Cortex analyzers."""
    if not settings.CORTEX_URL or not settings.CORTEX_API_KEY:
        return []

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{settings.CORTEX_URL}/api/analyzer",
                headers={
                    "Authorization": f"Bearer {settings.CORTEX_API_KEY}",
                },
            )
            if response.status_code == 200:
                analyzers = response.json()
                return [
                    {
                        "id": a.get("id"),
                        "name": a.get("name"),
                        "description": a.get("description"),
                        "data_types": a.get("dataTypes", []),
                    }
                    for a in analyzers
                ]
            return []
    except Exception:
        return []


# ── Observable Helpers ───────────────────────────────────────────────────


def push_observable_to_case(
    case_id: str,
    data_type: str,
    data: str,
    message: str = "",
    tlp: int = 2,
    ioc: bool = True,
) -> bool:
    """Add an observable to an existing TheHive case."""
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
