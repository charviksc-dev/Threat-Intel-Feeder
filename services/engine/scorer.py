"""Advanced Scoring System - Confidence + Severity scoring.

Confidence Score (0-100): How confident we are this indicator is malicious
Severity Score (0-100): How dangerous this indicator is
Final Score: Weighted combination

Scoring factors:
- Source count (more sources = higher confidence)
- Source reputation (some feeds are more trusted)
- Threat type (C2 > phishing > scan)
- Age (newer = more concerning)
- VirusTotal detections
- Correlation boost
"""

import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

# Source trust weights (0-1)
SOURCE_WEIGHTS = {
    "virustotal": 0.9,
    "misp": 0.85,
    "hybrid-analysis": 0.85,
    "greynoise": 0.8,
    "spamhaus": 0.8,
    "feodo-tracker": 0.8,
    "urlhaus": 0.75,
    "threatfox": 0.75,
    "emerging-threats": 0.7,
    "otx": 0.65,
    "abusech": 0.7,
    "openphish": 0.7,
    "phishtank": 0.65,
    "hibp": 0.6,
    "suricata": 0.7,
    "wazuh": 0.7,
    "zeek": 0.65,
    "webhook": 0.5,
    "firewall": 0.6,
}

# Threat type severity weights
THREAT_SEVERITY = {
    "malware": 0.9,
    "ransomware": 1.0,
    "botnet-c2": 0.95,
    "c2": 0.95,
    "malware-c2": 0.95,
    "apt": 1.0,
    "exploit": 0.85,
    "phishing": 0.7,
    "spam": 0.3,
    "scan": 0.4,
    "bruteforce": 0.5,
    "background-noise": 0.2,
    "benign-traffic": 0.1,
    "compromised": 0.7,
    "blocked": 0.5,
    "data-breach": 0.8,
    "ids-alert": 0.6,
}

# Type severity
TYPE_SEVERITY = {
    "hash": 0.9,  # Malware hash = high concern
    "url": 0.7,
    "domain": 0.65,
    "ipv4": 0.6,
    "ipv6": 0.6,
    "cidr": 0.5,
    "email": 0.4,
    "cve": 0.8,
}


def calculate_confidence_score(indicator: dict[str, Any]) -> int:
    """Calculate confidence score (0-100) based on multiple factors."""
    score = 20  # Base score

    # Source count bonus
    source_count = (
        indicator.get("metadata", {}).get("correlation", {}).get("source_count", 1)
    )
    if source_count >= 5:
        score += 40
    elif source_count >= 3:
        score += 30
    elif source_count >= 2:
        score += 20

    # Source weight
    source = indicator.get("source", "")
    source_weight = SOURCE_WEIGHTS.get(source, 0.5)
    score += int(source_weight * 20)

    # VirusTotal detections
    vt_score = indicator.get("metadata", {}).get("virustotal", {}).get("vt_score")
    if vt_score and isinstance(vt_score, (int, float)):
        if vt_score >= 10:
            score += 15
        elif vt_score >= 5:
            score += 10
        elif vt_score >= 1:
            score += 5

    # Correlation boost
    boost = indicator.get("_confidence_boost", 0)
    score += boost

    # Age penalty (older indicators less relevant)
    first_seen = indicator.get("first_seen")
    if first_seen:
        try:
            if isinstance(first_seen, str):
                first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                age_days = (datetime.utcnow() - first_dt.replace(tzinfo=None)).days
                if age_days > 365:
                    score -= 15
                elif age_days > 90:
                    score -= 5
        except Exception:
            pass

    return min(100, max(0, score))


def calculate_severity_score(indicator: dict[str, Any]) -> int:
    """Calculate severity score (0-100) based on threat type and impact."""
    score = 10  # Base severity

    # Threat type severity
    threat_types = indicator.get("threat_types", [])
    max_threat_sev = max(
        (THREAT_SEVERITY.get(t, 0.3) for t in threat_types), default=0.3
    )
    score += int(max_threat_sev * 50)

    # Type severity
    ind_type = indicator.get("type", "")
    type_sev = TYPE_SEVERITY.get(ind_type, 0.5)
    score += int(type_sev * 20)

    # Critical tags
    tags = [t.lower() for t in indicator.get("tags", [])]
    if any("ransomware" in t for t in tags):
        score += 15
    if any("apt" in t for t in tags):
        score += 15
    if any("zero-day" in t or "0day" in t for t in tags):
        score += 20

    return min(100, max(0, score))


def score_indicator(indicator: dict[str, Any]) -> dict[str, Any]:
    """Apply full scoring to an indicator."""
    confidence = calculate_confidence_score(indicator)
    severity = calculate_severity_score(indicator)

    # Combined score (weighted)
    combined = int(confidence * 0.6 + severity * 0.4)

    # Severity label
    if combined >= 80:
        severity_label = "critical"
    elif combined >= 60:
        severity_label = "high"
    elif combined >= 35:
        severity_label = "medium"
    else:
        severity_label = "low"

    indicator["confidence_score"] = combined
    indicator["severity"] = severity_label
    indicator["confidence_raw"] = confidence
    indicator["severity_raw"] = severity

    return indicator


def score_batch(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score a batch of indicators."""
    return [score_indicator(ind) for ind in indicators]
