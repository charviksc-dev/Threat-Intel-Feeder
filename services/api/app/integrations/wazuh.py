"""Wazuh SIEM Integration

Receives alerts from Wazuh via:
1. Wazuh Active Response webhook (wazuh sends alerts to this API)
2. Wazuh syslog output (parsed from syslog)

Extracts IOCs from Wazuh alerts:
- Source IPs from auth failures, intrusion attempts
- Malware hashes from VirusTotal integrations
- Domains from DNS queries

Pushes correlated alerts to TheHive for case management.
"""

import json
import logging
from datetime import datetime
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def parse_wazuh_alert(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract IOCs from a Wazuh alert JSON.

    Wazuh alert format:
    {
        "timestamp": "2024-01-01T00:00:00Z",
        "rule": {"id": "5710", "level": 10, "description": "..."},
        "agent": {"id": "001", "name": "web-server-01"},
        "data": {"srcip": "1.2.3.4", "dstip": "5.6.7.8"},
        "full_log": "..."
    }
    """
    indicators = []
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    timestamp = alert.get("timestamp")
    rule_id = str(rule.get("id", ""))
    rule_desc = rule.get("description", "")
    severity = rule.get("level", 0)

    # Map Wazuh severity to threat types
    threat_types = []
    if severity >= 10:
        threat_types.append("critical")
    elif severity >= 7:
        threat_types.append("high")
    elif severity >= 4:
        threat_types.append("medium")
    else:
        threat_types.append("low")

    # Extract source IPs
    src_ip = data.get("srcip") or data.get("src_ip")
    if src_ip:
        indicators.append(
            {
                "indicator": src_ip,
                "type": "ipv4",
                "source": "wazuh",
                "first_seen": timestamp,
                "threat_types": threat_types,
                "tags": [f"rule:{rule_id}", f"agent:{agent.get('name', 'unknown')}"],
                "metadata": {
                    "wazuh_rule_id": rule_id,
                    "wazuh_rule_desc": rule_desc,
                    "wazuh_severity": severity,
                    "wazuh_agent": agent.get("name"),
                    "wazuh_agent_id": agent.get("id"),
                    "raw_alert": alert,
                },
            }
        )

    # Extract destination IPs
    dst_ip = data.get("dstip") or data.get("dst_ip")
    if dst_ip and dst_ip != src_ip:
        indicators.append(
            {
                "indicator": dst_ip,
                "type": "ipv4",
                "source": "wazuh",
                "first_seen": timestamp,
                "threat_types": threat_types,
                "tags": [f"rule:{rule_id}"],
                "metadata": {
                    "wazuh_rule_id": rule_id,
                    "wazuh_rule_desc": rule_desc,
                    "direction": "destination",
                },
            }
        )

    # Extract domains from DNS queries
    domain = data.get("domain") or data.get("query")
    if domain:
        indicators.append(
            {
                "indicator": domain,
                "type": "domain",
                "source": "wazuh",
                "first_seen": timestamp,
                "threat_types": threat_types,
                "tags": [f"rule:{rule_id}"],
                "metadata": {
                    "wazuh_rule_id": rule_id,
                    "wazuh_rule_desc": rule_desc,
                },
            }
        )

    # Extract file hashes
    for hash_field in ["md5", "sha1", "sha256", "file_md5", "file_sha256"]:
        hash_value = data.get(hash_field)
        if hash_value:
            indicators.append(
                {
                    "indicator": hash_value,
                    "type": "hash",
                    "source": "wazuh",
                    "first_seen": timestamp,
                    "threat_types": threat_types,
                    "tags": [f"rule:{rule_id}", hash_field],
                    "metadata": {
                        "wazuh_rule_id": rule_id,
                        "wazuh_rule_desc": rule_desc,
                        "hash_type": hash_field,
                    },
                }
            )

    # Extract URLs
    url = data.get("url")
    if url:
        indicators.append(
            {
                "indicator": url,
                "type": "url",
                "source": "wazuh",
                "first_seen": timestamp,
                "threat_types": threat_types,
                "tags": [f"rule:{rule_id}"],
                "metadata": {
                    "wazuh_rule_id": rule_id,
                    "wazuh_rule_desc": rule_desc,
                },
            }
        )

    return indicators


def extract_wazuh_alert_metadata(alert: dict[str, Any]) -> dict[str, Any]:
    """Extract metadata for alert storage."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    return {
        "alert_id": f"wazuh-{agent.get('id', '000')}-{rule.get('id', '0')}-{alert.get('timestamp', '')}",
        "source": "wazuh",
        "severity": _map_severity(rule.get("level", 0)),
        "category": rule.get("groups", ["unknown"])[0]
        if rule.get("groups")
        else "unknown",
        "payload": alert,
    }


def _map_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    elif level >= 7:
        return "high"
    elif level >= 4:
        return "medium"
    return "low"


def push_to_thehive(alert_meta: dict[str, Any]) -> bool:
    """Push a Wazuh alert to TheHive as an alert/case."""
    if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
        return False

    hive_alert = {
        "title": f"[Wazuh] {alert_meta['payload'].get('rule', {}).get('description', 'Unknown Alert')}",
        "description": json.dumps(alert_meta["payload"], indent=2),
        "type": "wazuh",
        "source": "wazuh",
        "sourceRef": alert_meta["alert_id"],
        "severity": _hive_severity(alert_meta["severity"]),
        "tags": [
            f"wazuh:rule:{alert_meta['payload'].get('rule', {}).get('id', '')}",
            f"wazuh:agent:{alert_meta['payload'].get('agent', {}).get('name', '')}",
        ],
        "tlp": 2,  # AMBER
        "pap": 2,  # AMBER
    }

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{settings.THEHIVE_URL}/api/alert",
                json=hive_alert,
                headers={
                    "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201):
                logger.info("Pushed alert %s to TheHive", alert_meta["alert_id"])
                return True
            else:
                logger.warning(
                    "TheHive returned %d: %s", response.status_code, response.text
                )
                return False
    except Exception as e:
        logger.warning("Failed to push to TheHive: %s", e)
        return False


def _hive_severity(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 2)
