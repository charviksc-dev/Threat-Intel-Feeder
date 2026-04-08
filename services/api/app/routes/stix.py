"""STIX 2.1 Export - Industry standard threat intelligence sharing."""

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from elasticsearch import AsyncElasticsearch

from ..dependencies import get_elasticsearch
from ..config import settings

router = APIRouter(prefix="/api/v1", tags=["stix"])

# MITRE ATT&CK technique mapping for common threat types
ATTACK_MAPPING = {
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "initial-access",
    },
    "bruteforce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "credential-access",
    },
    "malware": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "execution",
    },
    "ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "impact",
    },
    "c2": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
    },
    "botnet-c2": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
    },
    "malware-c2": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
    },
    "scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "discovery",
    },
    "exploit": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "execution",
    },
    "data-breach": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
    },
    "compromised": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
    },
    "spam": {
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "tactic": "initial-access",
    },
}

# STIX type mapping
STIX_SCO_TYPES = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "url": "url",
    "hash": "file",
    "email": "email-addr",
    "cidr": "ipv4-addr",
}


def indicator_to_stix(indicator: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Neev indicator to STIX 2.1 objects."""
    objects = []
    now = datetime.now(timezone.utc).isoformat()
    ind_value = indicator.get("indicator", "")
    ind_type = indicator.get("type", "")

    # Create STIX Observable (SCO)
    sco_type = STIX_SCO_TYPES.get(ind_type, "indicator")

    if sco_type == "ipv4-addr":
        sco = {
            "type": "ipv4-addr",
            "id": f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "value": ind_value,
        }
    elif sco_type == "ipv6-addr":
        sco = {
            "type": "ipv6-addr",
            "id": f"ipv6-addr--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "value": ind_value,
        }
    elif sco_type == "domain-name":
        sco = {
            "type": "domain-name",
            "id": f"domain-name--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "value": ind_value,
        }
    elif sco_type == "url":
        sco = {
            "type": "url",
            "id": f"url--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "value": ind_value,
        }
    elif sco_type == "email-addr":
        sco = {
            "type": "email-addr",
            "id": f"email-addr--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "value": ind_value,
        }
    elif sco_type == "file":
        hash_type = "MD5"
        if len(ind_value) == 64:
            hash_type = "SHA-256"
        elif len(ind_value) == 40:
            hash_type = "SHA-1"
        sco = {
            "type": "file",
            "id": f"file--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "hashes": {hash_type: ind_value},
        }
    else:
        sco = {
            "type": sco_type,
            "id": f"{sco_type}--{uuid.uuid5(uuid.NAMESPACE_URL, ind_value)}",
            "value": ind_value,
        }

    objects.append(sco)

    # Create STIX Indicator (SDO)
    confidence = indicator.get("confidence_score", 50)
    threat_types = indicator.get("threat_types", [])
    source = indicator.get("source", "neeve")

    # Build STIX pattern
    pattern = _build_stix_pattern(ind_type, ind_value, sco.get("hashes"))

    # Map to ATT&CK
    attack_refs = []
    for tt in threat_types:
        mapping = ATTACK_MAPPING.get(tt.lower())
        if mapping:
            attack_refs.append(
                {
                    "external_id": mapping["technique_id"],
                    "source_name": "mitre-attack",
                    "url": f"https://attack.mitre.org/techniques/{mapping['technique_id'].replace('.', '/')}",
                }
            )

    indicator_sdo = {
        "type": "indicator",
        "id": f"indicator--{uuid.uuid4()}",
        "created": indicator.get("first_seen", now),
        "modified": indicator.get("last_seen", now),
        "name": f"{ind_type.upper()} indicator: {ind_value[:50]}",
        "description": f"Threat indicator from {source}. Threat types: {', '.join(threat_types)}",
        "indicator_types": [
            "malicious-activity" if confidence > 50 else "anomalous-activity"
        ],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": indicator.get("first_seen", now),
        "confidence": confidence,
        "labels": indicator.get("tags", []),
        "external_references": [
            {"source_name": source, "description": f"Neev TIP source: {source}"}
        ]
        + attack_refs,
    }
    objects.append(indicator_sdo)

    # Create Relationship if geo data exists
    geo = indicator.get("geo") or {}
    if geo and geo.get("country"):
        location_sdo = {
            "type": "location",
            "id": f"location--{uuid.uuid5(uuid.NAMESPACE_URL, geo.get('country', ''))}",
            "country": geo.get("country"),
            "region": geo.get("region"),
            "city": geo.get("city"),
        }
        objects.append(location_sdo)

        relationship = {
            "type": "relationship",
            "id": f"relationship--{uuid.uuid4()}",
            "relationship_type": "originates-from",
            "source_ref": sco.get("id"),
            "target_ref": location_sdo["id"],
            "created": now,
        }
        objects.append(relationship)

    return objects


def _build_stix_pattern(ind_type: str, value: str, hashes: dict | None = None) -> str:
    """Build a STIX pattern expression."""
    if ind_type == "ipv4":
        return f"[ipv4-addr:value = '{value}']"
    elif ind_type == "ipv6":
        return f"[ipv6-addr:value = '{value}']"
    elif ind_type == "domain":
        return f"[domain-name:value = '{value}']"
    elif ind_type == "url":
        return f"[url:value = '{value}']"
    elif ind_type == "email":
        return f"[email-addr:value = '{value}']"
    elif ind_type == "hash" and hashes:
        hash_key = list(hashes.keys())[0]
        return f"[file:hashes.{hash_key} = '{value}']"
    elif ind_type == "cidr":
        return f"[ipv4-addr:value = '{value}']"
    return f"[indicator:value = '{value}']"


@router.get("/stix/export")
async def export_stix_bundle(
    source: str | None = Query(None, description="Filter by source"),
    min_score: float = Query(0, description="Minimum confidence score"),
    limit: int = Query(100, ge=1, le=1000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as a STIX 2.1 Bundle.

    Compatible with:
    - OpenCTI (import STIX bundles)
    - MISP (import STIX 2.1)
    - Splunk SOAR (STIX ingestion)
    - Microsoft Sentinel (STIX connector)
    - Any TAXII 2.1 client
    """
    query = {"bool": {"filter": [{"range": {"confidence_score": {"gte": min_score}}}]}}
    if source:
        query["bool"]["filter"].append({"term": {"source": source}})

    body = {"query": query, "size": limit, "sort": [{"confidence_score": "desc"}]}
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)

    all_objects = []
    seen_ids = set()

    for hit in response["hits"]["hits"]:
        indicator = hit["_source"]
        objects = indicator_to_stix(indicator)
        for obj in objects:
            if obj["id"] not in seen_ids:
                seen_ids.add(obj["id"])
                all_objects.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": all_objects,
    }

    return JSONResponse(
        content=bundle,
        headers={
            "Content-Disposition": f"attachment; filename=neeve-stix-export-{datetime.now().strftime('%Y%m%d')}.json"
        },
    )


@router.get("/attack/coverage")
async def attack_coverage(
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Get MITRE ATT&CK coverage map based on current indicators."""
    body = {
        "size": 0,
        "aggs": {
            "threat_types": {"terms": {"field": "threat_types", "size": 100}},
        },
    }
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)

    coverage = {}
    for bucket in response["aggregations"]["threat_types"]["buckets"]:
        tt = bucket["key"]
        mapping = ATTACK_MAPPING.get(tt)
        if mapping:
            tid = mapping["technique_id"]
            if tid not in coverage:
                coverage[tid] = {
                    "technique_id": tid,
                    "technique_name": mapping["technique_name"],
                    "tactic": mapping["tactic"],
                    "indicator_count": 0,
                    "threat_types": [],
                }
            coverage[tid]["indicator_count"] += bucket["doc_count"]
            coverage[tid]["threat_types"].append(tt)

    # Organize by tactic
    by_tactic = {}
    for tech in coverage.values():
        tactic = tech["tactic"]
        if tactic not in by_tactic:
            by_tactic[tactic] = []
        by_tactic[tactic].append(tech)

    return {
        "techniques": list(coverage.values()),
        "by_tactic": by_tactic,
        "total_techniques_covered": len(coverage),
    }
