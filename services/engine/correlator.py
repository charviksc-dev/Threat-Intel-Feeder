"""Correlation Engine - Links indicators across multiple sources.

When the same indicator appears in 2+ sources, confidence increases.
When related indicators (IP + domain from same malware family) appear together,
they get linked as a "cluster".
"""

import logging
from datetime import datetime
from typing import Any
from collections import defaultdict

logger = logging.getLogger(__name__)


def correlate_indicators(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate indicators across sources and boost confidence.

    Rules:
    - Same indicator in 2+ sources → +20 confidence
    - Same indicator in 3+ sources → +35 confidence
    - Same indicator in 5+ sources → +50 confidence
    - Related IOCs from same malware family → linked as cluster
    """
    # Group by indicator value
    by_value = defaultdict(list)
    for ind in indicators:
        key = ind.get("indicator", "").lower()
        if key:
            by_value[key].append(ind)

    correlated = []
    for value, sources in by_value.items():
        source_count = len(sources)

        # Take the first as base, merge metadata from others
        base = sources[0].copy()

        # Merge sources
        all_sources = list(set(s.get("source", "") for s in sources))
        all_tags = list(set(t for s in sources for t in s.get("tags", [])))
        all_threat_types = list(
            set(t for s in sources for t in s.get("threat_types", []))
        )

        # Merge metadata
        merged_meta = {}
        for s in sources:
            merged_meta.update(s.get("metadata", {}))
        merged_meta["correlation"] = {
            "source_count": source_count,
            "sources": all_sources,
            "first_seen_min": min(
                (s.get("first_seen") for s in sources if s.get("first_seen")),
                default=None,
            ),
            "last_seen_max": max(
                (s.get("last_seen") for s in sources if s.get("last_seen")),
                default=None,
            ),
        }

        base["metadata"] = merged_meta
        base["tags"] = all_tags
        base["threat_types"] = all_threat_types

        # Confidence boost based on source count
        if source_count >= 5:
            base["_confidence_boost"] = 50
        elif source_count >= 3:
            base["_confidence_boost"] = 35
        elif source_count >= 2:
            base["_confidence_boost"] = 20
        else:
            base["_confidence_boost"] = 0

        correlated.append(base)

    logger.info(
        "Correlated %d unique indicators from %d raw", len(correlated), len(indicators)
    )
    return correlated


def build_clusters(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group related indicators into clusters based on:
    - Same malware family in tags
    - Same threat campaign
    - Same ASN/network
    """
    clusters = defaultdict(list)

    for ind in indicators:
        # Cluster by malware family
        for tag in ind.get("tags", []):
            tag_lower = tag.lower()
            if any(
                fam in tag_lower
                for fam in [
                    "emotet",
                    "trickbot",
                    "qakbot",
                    "cobalt",
                    "apt",
                    "lazarus",
                    "conti",
                    "lockbit",
                    "ransomware",
                ]
            ):
                clusters[f"malware:{tag}"].append(ind["indicator"])

        # Cluster by ASN
        asn = ind.get("metadata", {}).get("asn") or ind.get("geo", {}).get("asn")
        if asn:
            clusters[f"asn:{asn}"].append(ind["indicator"])

    # Attach cluster info to indicators
    indicator_to_cluster = {}
    for cluster_id, members in clusters.items():
        if len(members) >= 2:  # Only meaningful clusters
            for member in members:
                if member not in indicator_to_cluster:
                    indicator_to_cluster[member] = []
                indicator_to_cluster[member].append(
                    {
                        "cluster_id": cluster_id,
                        "member_count": len(members),
                    }
                )

    for ind in indicators:
        ind["clusters"] = indicator_to_cluster.get(ind["indicator"], [])

    return indicators
