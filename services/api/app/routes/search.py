"""Search, Threat Hunting, and AI Analysis API Routes."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query, HTTPException
from elasticsearch import AsyncElasticsearch

from ..dependencies import get_elasticsearch
from ..config import settings
from ..services.ai_engine import ai_engine

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
    """Generate AI threat analysis using synthetic intelligence engine."""
    # Fetch indicators from Elasticsearch
    if indicators:
        indicator_list = [i.strip() for i in indicators.split(",")]
        body = {
            "query": {"terms": {"indicator": indicator_list}},
            "size": 100,
        }
    else:
        # Analyze recent indicators
        body = {
            "query": {
                "range": {"first_seen": {"gte": "now-24h"}}
            },
            "size": 500,
        }
    
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicator_data = [hit["_source"] for hit in response["hits"]["hits"]]
    
    # Run AI analysis
    patterns = ai_engine.analyze_patterns(indicator_data)
    anomalies = ai_engine.detect_anomalies(indicator_data)
    attack_chain = ai_engine.reconstruct_attack_chain(indicator_data)
    
    # Calculate overall threat score
    if indicator_data:
        avg_score = sum(
            ai_engine.calculate_threat_score(ind) for ind in indicator_data
        ) / len(indicator_data)
    else:
        avg_score = 0
    
    analysis_result = {
        "id": f"analysis-{len(AI_ANALYSIS_HISTORY) + 1}",
        "timestamp": datetime.now().isoformat(),
        "total_indicators_analyzed": len(indicator_data),
        "model": "Neev TIP Synthetic Intelligence Engine v3.0",
        "overall_threat_score": round(avg_score, 2),
        "detected_patterns": [
            {
                "type": p.pattern_type,
                "confidence": round(p.confidence, 2),
                "severity": p.severity,
                "description": p.description,
                "mitre_techniques": p.mitre_techniques,
                "indicator_count": len(p.indicators),
                "sample_indicators": p.indicators[:5],
            }
            for p in patterns
        ],
        "detected_anomalies": [
            {
                "type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "score": round(a.score, 2),
                "affected_count": len(a.affected_indicators),
                "sample_indicators": a.affected_indicators[:5],
            }
            for a in anomalies
        ],
        "attack_chain_analysis": attack_chain,
        "recommendations": _generate_recommendations(patterns, anomalies, attack_chain),
        "confidence_uncertainty": "±3",
    }
    
    AI_ANALYSIS_HISTORY.append(analysis_result)
    if len(AI_ANALYSIS_HISTORY) > 20:
        AI_ANALYSIS_HISTORY.pop(0)
    
    return analysis_result


@router.get("/ai/patterns")
async def ai_detect_patterns(
    q: str = Query("", description="Search query"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Detect threat patterns in indicators."""
    body = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"first_seen": {"gte": "now-7d"}}}
                ]
            }
        } if not q else {
            "bool": {
                "must": [
                    {"multi_match": {"query": q, "fields": ["indicator", "description", "tags"]}},
                    {"range": {"first_seen": {"gte": "now-7d"}}}
                ]
            }
        },
        "size": 500,
    }
    
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicator_data = [hit["_source"] for hit in response["hits"]["hits"]]
    
    patterns = ai_engine.analyze_patterns(indicator_data)
    
    return {
        "indicators_analyzed": len(indicator_data),
        "patterns_detected": len(patterns),
        "patterns": [
            {
                "type": p.pattern_type,
                "confidence": round(p.confidence, 2),
                "severity": p.severity,
                "description": p.description,
                "mitre_techniques": p.mitre_techniques,
                "indicator_count": len(p.indicators),
                "indicators": p.indicators,
            }
            for p in patterns
        ],
    }


@router.get("/ai/anomalies")
async def ai_detect_anomalies(
    hours: int = Query(24, description="Time window in hours"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Detect behavioral anomalies in indicators."""
    body = {
        "query": {
            "range": {"first_seen": {"gte": f"now-{hours}h"}}
        },
        "size": 1000,
    }
    
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicator_data = [hit["_source"] for hit in response["hits"]["hits"]]
    
    anomalies = ai_engine.detect_anomalies(indicator_data)
    
    return {
        "time_window_hours": hours,
        "indicators_analyzed": len(indicator_data),
        "anomalies_detected": len(anomalies),
        "anomalies": [
            {
                "type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "score": round(a.score, 2),
                "affected_count": len(a.affected_indicators),
                "indicators": a.affected_indicators,
            }
            for a in anomalies
        ],
    }


@router.get("/ai/attack-chain")
async def ai_reconstruct_attack_chain(
    indicator: str = Query(..., description="Indicator value"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Reconstruct attack chain for a specific indicator."""
    body = {
        "query": {"term": {"indicator": indicator}},
        "size": 100,
    }
    
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    indicator_data = [hit["_source"] for hit in response["hits"]["hits"]]
    
    if not indicator_data:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    # Find related indicators (same threat types, similar patterns)
    threat_types = indicator_data[0].get("threat_types", [])
    body_related = {
        "query": {
            "bool": {
                "should": [
                    {"terms": {"threat_types": threat_types}},
                    {"match": {"tags": indicator_data[0].get("tags", [])}},
                ],
                "minimum_should_match": 1,
            }
        },
        "size": 200,
    }
    
    related_response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body_related)
    related_indicators = [hit["_source"] for hit in related_response["hits"]["hits"]]
    
    attack_chain = ai_engine.reconstruct_attack_chain(related_indicators)
    
    # Calculate threat score
    threat_score = ai_engine.calculate_threat_score(indicator_data[0])
    
    return {
        "indicator": indicator,
        "threat_score": round(threat_score, 2),
        "attack_chain": attack_chain,
        "related_indicators_count": len(related_indicators),
        "sample_related_indicators": [ind["indicator"] for ind in related_indicators[:10]],
    }


@router.get("/ai/predict")
async def ai_predict_trend(
    days: int = Query(30, description="Historical days to analyze"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Predict threat trends based on historical data."""
    body = {
        "query": {
            "range": {"first_seen": {"gte": f"now-{days}d"}}
        },
        "size": 5000,
        "sort": [{"first_seen": {"order": "asc"}}],
    }
    
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    historical_data = [hit["_source"] for hit in response["hits"]["hits"]]
    
    prediction = ai_engine.predict_threat_trend(historical_data)
    
    return prediction


@router.get("/ai/score")
async def ai_calculate_score(
    indicator: str = Query(..., description="Indicator value"),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Calculate ML-based threat score for an indicator."""
    body = {
        "query": {"term": {"indicator": indicator}},
        "size": 1,
    }
    
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    hits = response["hits"]["hits"]
    
    if not hits:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    indicator_data = hits[0]["_source"]
    threat_score = ai_engine.calculate_threat_score(indicator_data)
    
    return {
        "indicator": indicator,
        "threat_score": round(threat_score, 2),
        "score_breakdown": {
            "source_reliability": 0.25 * (
                100 if indicator_data.get("source") in ["virustotal", "otx", "misp"]
                else 80 if indicator_data.get("source") in ["urlhaus", "threatfox"]
                else 60
            ),
            "recency": 0.20 * 50,  # Simplified
            "threat_type_severity": 0.15 * (
                100 if any(t in ["malware", "c2", "phishing", "ransomware"] for t in indicator_data.get("threat_types", []))
                else 70
            ),
            "geographic_risk": 0.10 * (
                80 if indicator_data.get("geo", {}).get("country") in ["CN", "RU", "KP", "IR", "SY"]
                else 40 if indicator_data.get("geo", {}).get("country")
                else 20
            ),
            "correlation_count": 0.20 * (indicator_data.get("confidence_score", 0.5) * 100),
            "behavioral_anomaly": 0.10 * 50,
        },
    }


@router.get("/ai/history")
async def ai_history():
    """Get AI analysis history."""
    return AI_ANALYSIS_HISTORY[-10:]


@router.post("/ai/feedback")
async def ai_feedback(
    analysis_id: str,
    is_positive: bool,
    comment: str | None = None,
):
    """Submit analyst feedback on AI analysis for model improvement."""
    logger.info(
        f"AI feedback: {analysis_id} - {'positive' if is_positive else 'negative'} - {comment or 'no comment'}"
    )
    return {"status": "recorded", "analysis_id": analysis_id}


def _generate_recommendations(patterns, anomalies, attack_chain):
    """Generate actionable recommendations based on analysis."""
    recommendations = []
    
    # Pattern-based recommendations
    for pattern in patterns:
        if pattern.pattern_type == "c2_infrastructure":
            recommendations.append({
                "priority": "high",
                "action": "Block identified C2 infrastructure in perimeter firewalls",
                "details": f"Detected {len(pattern.indicators)} C2 indicators with {round(pattern.confidence * 100)}% confidence",
            })
        elif pattern.pattern_type == "phishing_kit":
            recommendations.append({
                "priority": "critical",
                "action": "Block phishing domains and alert security team",
                "details": f"Active phishing kit detected with {len(pattern.indicators)} domains",
            })
        elif pattern.pattern_type == "malware_family":
            recommendations.append({
                "priority": "critical",
                "action": "Isolate affected systems and initiate incident response",
                "details": f"Known malware family indicators detected: {pattern.pattern_type}",
            })
    
    # Anomaly-based recommendations
    for anomaly in anomalies:
        if anomaly.anomaly_type == "temporal_surge":
            recommendations.append({
                "priority": "high",
                "action": "Investigate sudden surge in threat indicators",
                "details": anomaly.description,
            })
        elif anomaly.anomaly_type == "asn_concentration":
            recommendations.append({
                "priority": "medium",
                "action": "Review and potentially block high-risk ASN",
                "details": anomaly.description,
            })
    
    # Attack chain recommendations
    if attack_chain["completion_percentage"] > 50:
        recommendations.append({
            "priority": "high",
            "action": "Full attack chain detected - immediate incident response required",
            "details": f"Attack chain {attack_chain['completion_percentage']}% complete with stages: {', '.join(attack_chain['detected_stages'])}",
        })
    
    if not recommendations:
        recommendations.append({
            "priority": "low",
            "action": "Continue monitoring",
            "details": "No immediate threats detected",
        })
    
    return recommendations
