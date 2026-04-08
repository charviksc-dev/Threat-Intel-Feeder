"""AI Layer - Threat intelligence summarization and analysis.

Provides:
- IOC summarization (natural language description)
- Threat clustering analysis
- Auto-triage recommendations
- Pattern detection
"""

import logging
from typing import Any
from collections import Counter

logger = logging.getLogger(__name__)


def summarize_indicator(indicator: dict[str, Any]) -> str:
    """Generate a natural language summary for an indicator."""
    ind_value = indicator.get("indicator", "unknown")
    ind_type = indicator.get("type", "unknown")
    source = indicator.get("source", "unknown")
    threat_types = indicator.get("threat_types", [])
    confidence = indicator.get("confidence_score", 0)
    indicator.get("severity", "unknown")
    source_count = (
        indicator.get("metadata", {}).get("correlation", {}).get("source_count", 1)
    )
    sources = (
        indicator.get("metadata", {}).get("correlation", {}).get("sources", [source])
    )

    # Build summary parts
    parts = []

    # Opening
    if ind_type == "ipv4":
        geo = indicator.get("geo", {})
        country = geo.get("country", "unknown location")
        parts.append(f"IP address {ind_value} located in {country}")
    elif ind_type == "domain":
        parts.append(f"Domain {ind_value}")
    elif ind_type == "url":
        parts.append(f"URL {ind_value[:60]}{'...' if len(ind_value) > 60 else ''}")
    elif ind_type == "hash":
        hash_type = (
            "SHA256"
            if len(ind_value) == 64
            else "MD5"
            if len(ind_value) == 32
            else "SHA1"
        )
        parts.append(f"File hash ({hash_type}) {ind_value[:20]}...")
    else:
        parts.append(f"Indicator {ind_value}")

    # Threat context
    if threat_types:
        threat_str = ", ".join(threat_types[:3])
        parts.append(f"associated with {threat_str}")

    # Multi-source intelligence
    if source_count > 1:
        parts.append(
            f"confirmed by {source_count} intelligence sources ({', '.join(sources[:4])})"
        )
    else:
        parts.append(f"reported by {source}")

    # Severity assessment
    if confidence >= 80:
        parts.append("This is a HIGH CONFIDENCE threat requiring immediate attention.")
    elif confidence >= 60:
        parts.append("This indicator should be monitored and potentially blocked.")
    elif confidence >= 40:
        parts.append("This indicator warrants monitoring.")
    else:
        parts.append("This indicator has limited confidence and should be verified.")

    return " ".join(parts)


def generate_batch_summary(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate a summary analysis for a batch of indicators."""
    if not indicators:
        return {"summary": "No indicators to analyze."}

    # Type distribution
    type_counts = Counter(ind.get("type", "unknown") for ind in indicators)

    # Source distribution
    source_counts = Counter(ind.get("source", "unknown") for ind in indicators)

    # Threat distribution
    threat_counts = Counter()
    for ind in indicators:
        for t in ind.get("threat_types", []):
            threat_counts[t] += 1

    # Severity distribution
    sev_counts = Counter(ind.get("severity", "unknown") for ind in indicators)

    # High confidence indicators
    high_conf = [ind for ind in indicators if ind.get("confidence_score", 0) >= 70]

    # Top countries
    country_counts = Counter()
    for ind in indicators:
        country = ind.get("geo", {}).get("country")
        if country:
            country_counts[country] += 1

    # Build summary
    summary_parts = [
        f"Analysis of {len(indicators)} indicators:",
        f"- {len(high_conf)} high-confidence threats detected",
    ]

    if threat_counts:
        top_threats = threat_counts.most_common(3)
        summary_parts.append(
            f"- Top threat types: {', '.join(f'{t[0]} ({t[1]})' for t in top_threats)}"
        )

    if country_counts:
        top_countries = country_counts.most_common(3)
        summary_parts.append(
            f"- Most affected countries: {', '.join(f'{c[0]} ({c[1]})' for c in top_countries)}"
        )

    if source_counts:
        top_sources = source_counts.most_common(3)
        summary_parts.append(
            f"- Most active sources: {', '.join(f'{s[0]} ({s[1]})' for s in top_sources)}"
        )

    critical_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)
    if critical_count or high_count:
        summary_parts.append(
            f"- ⚠️ {critical_count} critical, {high_count} high severity indicators require attention"
        )

    return {
        "summary": "\n".join(summary_parts),
        "stats": {
            "total": len(indicators),
            "by_type": dict(type_counts),
            "by_source": dict(source_counts),
            "by_severity": dict(sev_counts),
            "high_confidence": len(high_conf),
            "top_countries": dict(country_counts.most_common(5)),
            "top_threats": dict(threat_counts.most_common(5)),
        },
    }


def triage_indicator(indicator: dict[str, Any]) -> dict[str, Any]:
    """Auto-triage an indicator with recommended actions."""
    severity = indicator.get("severity", "low")
    confidence = indicator.get("confidence_score", 0)
    ind_type = indicator.get("type", "")
    threat_types = indicator.get("threat_types", [])

    actions = []
    priority = "low"

    if confidence >= 80 or severity == "critical":
        priority = "critical"
        actions = [
            "Block immediately in firewall",
            "Add to SIEM watchlist",
            "Create incident ticket",
            "Notify SOC team",
        ]
    elif confidence >= 60 or severity == "high":
        priority = "high"
        actions = [
            "Add to monitoring list",
            "Check for internal matches",
            "Consider blocking",
        ]
    elif confidence >= 40:
        priority = "medium"
        actions = [
            "Monitor for activity",
            "Enrich with additional sources",
        ]
    else:
        actions = [
            "Log for reference",
            "Review if seen again",
        ]

    # Type-specific actions
    if ind_type == "hash" and "malware" in str(threat_types):
        actions.append("Scan endpoints for this hash")
    elif ind_type == "domain" and "phishing" in str(threat_types):
        actions.append("Check DNS logs for resolution attempts")
    elif ind_type == "ipv4" and any("c2" in t.lower() for t in threat_types):
        actions.append("Check network logs for outbound connections")

    return {
        "indicator": indicator.get("indicator"),
        "priority": priority,
        "confidence": confidence,
        "recommended_actions": actions,
        "auto_block_recommended": priority in ("critical", "high") and confidence >= 70,
    }
