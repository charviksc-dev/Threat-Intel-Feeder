"""Notification Service - Push alerts to Slack, webhooks, email."""

import json
import logging
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


def send_slack_alert(alert: dict[str, Any]) -> bool:
    """Send alert to Slack webhook."""
    webhook_url = settings.SLACK_WEBHOOK_URL
    if not webhook_url:
        return False

    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }

    severity = alert.get("severity", "medium")
    emoji = severity_emoji.get(severity, "⚪")

    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Neev TIP Alert: {alert.get('rule_name', 'Unknown')}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Score:*\n{alert.get('confidence_score', 'N/A')}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Indicator:*\n`{alert.get('indicator', 'N/A')}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{alert.get('source', 'N/A')}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.get("description", "No description"),
                },
            },
        ]
    }

    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(webhook_url, json=message)
            return response.status_code == 200
    except Exception as e:
        logger.warning("Slack notification failed: %s", e)
        return False


def send_webhook_alert(alert: dict[str, Any], webhook_url: str) -> bool:
    """Send alert to generic webhook."""
    if not webhook_url:
        return False

    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(webhook_url, json=alert)
            return response.status_code < 400
    except Exception as e:
        logger.warning("Webhook notification failed: %s", e)
        return False


def send_alerts(alerts: list[dict[str, Any]]) -> dict[str, int]:
    """Send alerts to all configured notification channels."""
    results = {"slack": 0, "webhook": 0, "total": len(alerts)}

    for alert in alerts:
        # Slack
        if settings.SLACK_WEBHOOK_URL:
            if send_slack_alert(alert):
                results["slack"] += 1

        # Generic webhook
        if settings.ALERT_WEBHOOK_URL:
            if send_webhook_alert(alert, settings.ALERT_WEBHOOK_URL):
                results["webhook"] += 1

    return results
