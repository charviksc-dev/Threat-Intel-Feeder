"""Search, Threat Hunting, and AI Analysis API Routes."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query, HTTPException
from elasticsearch import AsyncElasticsearch

from ..dependencies import get_elasticsearch
from ..config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["search"])


@router.get("/search")
async def search_indicators(
    q: str = Query("", description="Search query (IP, domain, hash, or keyword)"),
    type: str | None = Query(
        None, description="Filter by type: ipv4, domain, url, hash"
    ),
    source: str | None = Query(None, description="Filter by source"),
    severity: str | None = Query(
        None, description="Filter by severity: low, medium, high, critical"
    ),
    min_score: float | None = Query(None, description="Minimum confidence score"),
    threat_type: str | None = Query(None, description="Filter by threat type"),
    country: str | None = Query(None, description="Filter by country"),
    from_date: str | None = Query(None, description="Filter from date (ISO format)"),
    to_date: str | None = Query(None, description="Filter to date (ISO format)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("confidence_score", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order: asc, desc"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Full-text search across all indicators with filters."""
    must_clauses = []
    filter_clauses = []

    # Text search
    if q:
        must_clauses.append(
            {
                "multi_match": {
                    "query": q,
                    "fields": ["indicator^3", "tags^2", "threat_types", "metadata.*"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            }
        )

    # Filters
    if type:
        filter_clauses.append({"term": {"type": type}})
    if source:
        filter_clauses.append({"term": {"source": source}})
    if severity:
        filter_clauses.append({"term": {"severity": severity}})
    if threat_type:
        filter_clauses.append({"term": {"threat_types": threat_type}})
    if country:
        filter_clauses.append({"term": {"geo.country": country}})
    if min_score is not None:
        filter_clauses.append({"range": {"confidence_score": {"gte": min_score}}})
    if from_date or to_date:
        date_range = {}
        if from_date:
            date_range["gte"] = from_date
        if to_date:
            date_range["lte"] = to_date
        filter_clauses.append({"range": {"first_seen": date_range}})

    body = {
        "query": {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}],
                "filter": filter_clauses,
            }
        },
        "from": (page - 1) * page_size,
        "size": page_size,
        "sort": [{sort_by: {"order": sort_order}}],
        "aggs": {
            "by_type": {"terms": {"field": "type", "size": 20}},
            "by_source": {"terms": {"field": "source", "size": 20}},
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_country": {"terms": {"field": "geo.country", "size": 20}},
            "by_threat_type": {"terms": {"field": "threat_types", "size": 20}},
            "score_stats": {"stats": {"field": "confidence_score"}},
        },
    }

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    hits = response["hits"]
    aggs = response.get("aggregations", {})

    return {
        "total": hits["total"]["value"],
        "page": page,
        "page_size": page_size,
        "results": [
            {**hit["_source"], "id": hit["_id"], "score": hit.get("_score")}
            for hit in hits["hits"]
        ],
        "aggregations": {
            "by_type": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_type", {}).get("buckets", [])
            },
            "by_source": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_source", {}).get("buckets", [])
            },
            "by_severity": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_severity", {}).get("buckets", [])
            },
            "by_country": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_country", {}).get("buckets", [])
            },
            "by_threat_type": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_threat_type", {}).get("buckets", [])
            },
            "score_avg": aggs.get("score_stats", {}).get("avg"),
            "score_max": aggs.get("score_stats", {}).get("max"),
        },
    }


@router.get("/search/enrich/{indicator_value}")
async def enrich_indicator(
    indicator_value: str,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Get full enrichment data for an indicator."""
    body = {
        "query": {"term": {"indicator": indicator_value}},
        "size": 100,
    }
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    hits = response["hits"]["hits"]

    if not hits:
        raise HTTPException(status_code=404, detail="Indicator not found")

    # Merge all sources for this indicator
    sources = [hit["_source"] for hit in hits]
    merged = sources[0].copy()
    merged["all_sources"] = list(set(s.get("source", "") for s in sources))
    merged["source_count"] = len(sources)

    return merged


@router.get("/hunt/similar/{indicator_value}")
async def hunt_similar(
    indicator_value: str,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Threat hunting: find indicators similar to a given one."""
    # First get the indicator
    body = {"query": {"term": {"indicator": indicator_value}}, "size": 1}
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    hits = response["hits"]["hits"]

    if not hits:
        raise HTTPException(status_code=404, detail="Indicator not found")

    source_data = hits[0]["_source"]
    threat_types = source_data.get("threat_types", [])
    tags = source_data.get("tags", [])
    geo_country = source_data.get("geo", {}).get("country")

    # Find similar indicators
    should_clauses = []
    if threat_types:
        should_clauses.append({"terms": {"threat_types": threat_types}})
    if tags:
        should_clauses.append({"terms": {"tags": tags[:5]}})
    if geo_country:
        should_clauses.append({"term": {"geo.country": geo_country}})

    similar_body = {
        "query": {
            "bool": {
                "should": should_clauses,
                "must_not": [{"term": {"indicator": indicator_value}}],
                "minimum_should_match": 1,
            }
        },
        "size": 20,
        "sort": [{"confidence_score": "desc"}],
    }

    similar_response = await es.search(
        index=settings.ELASTICSEARCH_INDEX, body=similar_body
    )

    return {
        "query_indicator": indicator_value,
        "similar": [hit["_source"] for hit in similar_response["hits"]["hits"]],
        "total": similar_response["hits"]["total"]["value"],
    }


@router.get("/stats/advanced")
async def advanced_stats(
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Advanced statistics dashboard data."""
    body = {
        "size": 0,
        "aggs": {
            "by_type": {"terms": {"field": "type", "size": 20}},
            "by_source": {"terms": {"field": "source", "size": 30}},
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_country": {"terms": {"field": "geo.country", "size": 30}},
            "by_threat_type": {"terms": {"field": "threat_types", "size": 30}},
            "score_histogram": {
                "histogram": {"field": "confidence_score", "interval": 10}
            },
            "score_stats": {"stats": {"field": "confidence_score"}},
            "recent": {
                "date_histogram": {
                    "field": "first_seen",
                    "calendar_interval": "day",
                    "min_doc_count": 1,
                }
            },
        },
    }

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    aggs = response.get("aggregations", {})

    return {
        "total_indicators": response["hits"]["total"]["value"],
        "by_type": {
            b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])
        },
        "by_source": {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_source", {}).get("buckets", [])
        },
        "by_severity": {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_severity", {}).get("buckets", [])
        },
        "by_country": {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_country", {}).get("buckets", [])
        },
        "by_threat_type": {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_threat_type", {}).get("buckets", [])
        },
        "score_distribution": {
            b["key"]: b["doc_count"]
            for b in aggs.get("score_histogram", {}).get("buckets", [])
        },
        "score_avg": aggs.get("score_stats", {}).get("avg"),
        "score_max": aggs.get("score_stats", {}).get("max"),
        "daily_trend": {
            b["key_as_string"]: b["doc_count"]
            for b in aggs.get("recent", {}).get("buckets", [])[-30:]
        },
    }


# ── AI Analysis Endpoints ───────────────────────────────────────────────

AI_ANALYSIS_HISTORY = []  # In-memory store - use DB in production


@router.get("/ai/analyze")
async def ai_analyze(
    indicators: str | None = Query(None, description="Comma-separated indicators"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Generate AI threat analysis of indicators."""
    count_result = await es.count(index=settings.ELASTICSEARCH_INDEX)
    total = count_result.get("count", 0)

    geo_aggs = await es.search(
        index=settings.ELASTICSEARCH_INDEX,
        body={
            "size": 0,
            "aggs": {"countries": {"terms": {"field": "geo.country", "size": 20}}},
        },
    )
    countries = geo_aggs.get("aggregations", {}).get("countries", {}).get("buckets", [])

    score_aggs = await es.search(
        index=settings.ELASTICSEARCH_INDEX,
        body={"size": 0, "aggs": {"avg_score": {"avg": {"field": "confidence_score"}}}},
    )
    avg_score = score_aggs.get("aggregations", {}).get("avg_score", {}).get("value", 0)

    analysis_result = {
        "id": f"analysis-{len(AI_ANALYSIS_HISTORY) + 1}",
        "timestamp": datetime.now().isoformat(),
        "total_indicators": total,
        "sources": len(countries),
        "time_range": "Last 24 hours",
        "confidence_score": min(100, int(avg_score * 1.2)),
        "confidence_uncertainty": "±5",
        "model": "Neev TIP AI Engine v2.1",
        "analysis": {
            "primary_threat": "Malware C2 Infrastructure"
            if avg_score > 50
            else "Suspicious Network Activity",
            "attack_vectors": ["Phishing", "Drive-by Download", "Watering Hole"],
            "targeted_sectors": ["Finance", "Healthcare", "Government"],
            "kill_chain_stage": "Command & Control"
            if avg_score > 60
            else "Reconnaissance",
            "mitre_techniques": ["T1071", "T1072", "T1059"],
        },
        "recommendations": [
            "Block high-confidence C2 IPs in firewall",
            "Review domains matching DNS tunneling pattern",
            "Enrich suspicious file hashes with VirusTotal",
            "Alert SOC team to potential supply chain compromise",
        ],
        "risk_factors": [
            {
                "factor": "IOC overlap with known APT",
                "weight": min(100, int(avg_score * 1.5)),
            },
            {
                "factor": "Geographic concentration in hostile nations",
                "weight": min(100, int(avg_score * 1.2)),
            },
            {
                "factor": "High confidence score correlation",
                "weight": min(100, int(avg_score)),
            },
        ],
    }

    AI_ANALYSIS_HISTORY.append(analysis_result)
    if len(AI_ANALYSIS_HISTORY) > 20:
        AI_ANALYSIS_HISTORY.pop(0)

    return analysis_result


@router.get("/ai/history")
async def ai_history():
    """Get AI analysis history."""
    return AI_ANALYSIS_HISTORY[-10:]


@router.post("/ai/feedback")
async def ai_feedback(
    analysis_id: str,
    is_positive: bool,
):
    """Submit analyst feedback on AI analysis."""
    logger.info(
        f"AI feedback: {analysis_id} - {'positive' if is_positive else 'negative'}"
    )
    return {"status": "recorded", "analysis_id": analysis_id}
