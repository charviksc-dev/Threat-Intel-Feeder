"""Alerting Engine - Rule-based threat alerting.

Triggers alerts when:
- New high-severity IOC appears
- IOC matches internal detection logs
- Correlation threshold exceeded
- Specific threat types detected
"""

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

ALERT_RULES = [
    {
        "name": "high-severity-ioc",
        "description": "New high-severity indicator detected",
        "condition": lambda ind: ind.get("confidence_score", 0) >= 70,
        "severity": "high",
    },
    {
        "name": "new-malware-hash",
        "description": "New malware hash detected",
        "condition": lambda ind: (
            ind.get("type") == "hash" and "malware" in str(ind.get("threat_types", []))
        ),
        "severity": "high",
    },
    {
        "name": "botnet-c2-detected",
        "description": "Botnet C2 indicator detected",
        "condition": lambda ind: any(
            "c2" in t.lower() for t in ind.get("threat_types", [])
        ),
        "severity": "critical",
    },
    {
        "name": "ransomware-indicator",
        "description": "Ransomware indicator detected",
        "condition": lambda ind: any(
            "ransomware" in t.lower()
            for t in ind.get("tags", [] + ind.get("threat_types", []))
        ),
        "severity": "critical",
    },
    {
        "name": "multi-source-correlation",
        "description": "Indicator seen in 3+ sources",
        "condition": lambda ind: (
            ind.get("metadata", {}).get("correlation", {}).get("source_count", 1) >= 3
        ),
        "severity": "medium",
    },
    {
        "name": "phishing-url",
        "description": "New phishing URL detected",
        "condition": lambda ind: (
            ind.get("type") == "url" and "phishing" in str(ind.get("threat_types", []))
        ),
        "severity": "medium",
    },
]


def evaluate_alerts(indicator: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate all alert rules against an indicator."""
    alerts = []

    for rule in ALERT_RULES:
        try:
            if rule["condition"](indicator):
                alerts.append(
                    {
                        "alert_id": f"{rule['name']}::{indicator.get('indicator', 'unknown')}",
                        "rule_name": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "indicator": indicator.get("indicator"),
                        "indicator_type": indicator.get("type"),
                        "source": indicator.get("source"),
                        "confidence_score": indicator.get("confidence_score"),
                        "timestamp": datetime.utcnow().isoformat(),
                        "tags": indicator.get("tags", []),
                        "threat_types": indicator.get("threat_types", []),
                    }
                )
        except Exception as e:
            logger.debug("Alert rule %s failed: %s", rule["name"], e)

    return alerts


def process_indicators_for_alerts(
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Process a batch of indicators and return triggered alerts."""
    all_alerts = []
    for ind in indicators:
        alerts = evaluate_alerts(ind)
        all_alerts.extend(alerts)

    if all_alerts:
        logger.info(
            "Generated %d alerts from %d indicators", len(all_alerts), len(indicators)
        )

    return all_alerts
