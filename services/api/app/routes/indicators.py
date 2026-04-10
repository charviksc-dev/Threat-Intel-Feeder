from fastapi import APIRouter, Depends, HTTPException, Query
import logging
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import NotFoundError
from asyncpg import Pool

from ..dependencies import get_postgres_pool, get_elasticsearch
from ..schemas import (
    IndicatorResponse,
    IOCType,
    FeedHealthResponse,
    FeedHealthUpdate,
    FeedStatus,
    ConflictResponse,
    DedupConfigResponse,
)
from ..config import settings
from .auth import get_current_token_payload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["indicators"])


def build_search_query(
    query: str | None,
    indicator_type: IOCType | None,
    source: str | None,
    min_score: float | None,
    max_score: float | None,
) -> dict:
    filters = []
    if indicator_type:
        filters.append({"term": {"type": indicator_type.value}})
    if source:
        filters.append({"term": {"source": source}})
    if min_score is not None or max_score is not None:
        range_filter = {}
        if min_score is not None:
            range_filter["gte"] = min_score
        if max_score is not None:
            range_filter["lte"] = max_score
        filters.append({"range": {"confidence_score": range_filter}})

    must = []
    if query:
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "fields": ["indicator^4", "source^2", "threat_types", "context"],
                    "fuzziness": "AUTO",
                }
            }
        )

    bool_query = {"bool": {}}
    if must:
        bool_query["bool"]["must"] = must
    if filters:
        bool_query["bool"]["filter"] = filters
    if not bool_query["bool"]:
        bool_query = {"match_all": {}}
    return bool_query


def serialize(doc: dict) -> dict:
    source = doc.get("_source", {})
    return {
        "id": doc.get("_id"),
        **source,
    }


@router.get("/indicators", response_model=list[IndicatorResponse])
async def search_indicators(
    query: str | None = Query(None),
    indicator_type: IOCType | None = Query(None, alias="type"),
    source: str | None = Query(None),
    min_score: float | None = Query(None),
    max_score: float | None = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=100),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: dict = Depends(get_current_token_payload),
) -> list[IndicatorResponse]:
    body = {
        "query": build_search_query(
            query, indicator_type, source, min_score, max_score
        ),
        "sort": [
            {"confidence_score": {"order": "desc"}},
            {"last_seen": {"order": "desc"}},
        ],
        "from": (page - 1) * size,
        "size": size,
    }
    index = settings.ELASTICSEARCH_INDEX
    response = await es.search(index=index, body=body)
    hits = response["hits"]["hits"]
    return [serialize(hit) for hit in hits]





@router.get("/sources")
async def list_sources(
    es: AsyncElasticsearch = Depends(get_elasticsearch),
) -> list[str]:
    body = {"size": 0, "aggs": {"sources": {"terms": {"field": "source", "size": 50}}}}
    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    buckets = response.get("aggregations", {}).get("sources", {}).get("buckets", [])
    return [bucket["key"] for bucket in buckets]


@router.get("/stats")
async def get_stats(
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    import time
    import logging

    l = logging.getLogger(__name__)
    start = time.perf_counter()
    try:
        count = await es.count(index=settings.ELASTICSEARCH_INDEX)
        count_val = count.get("count", 0)
    except Exception as e:
        l.error("Error fetching total count from ES: %s", e)
        count_val = 0

    try:
        latest = await es.search(
            index=settings.ELASTICSEARCH_INDEX,
            body={
                "query": {"match_all": {}},
                "sort": [{"last_seen": {"order": "desc"}}],
                "size": 5,
            },
        )
        latest_hits = [serialize(hit) for hit in latest["hits"]["hits"]]
    except Exception as e:
        l.error("Error fetching latest indicators from ES: %s", e)
        latest_hits = []

    try:
        geo_aggs = await es.search(
            index=settings.ELASTICSEARCH_INDEX,
            body={
                "size": 0,
                "query": {"exists": {"field": "geo.country"}},
                "aggs": {
                    "by_country": {"terms": {"field": "geo.country", "size": 20}},
                    "by_city": {"terms": {"field": "geo.city", "size": 15}},
                    "by_asn": {"terms": {"field": "geo.asn", "size": 10}},
                    "top_locations": {
                        "top_hits": {"size": 10, "_source": ["indicator", "geo"]}
                    },
                },
            },
        )
        country_buckets = (
            geo_aggs.get("aggregations", {}).get("by_country", {}).get("buckets", [])
        )
        asn_buckets = geo_aggs.get("aggregations", {}).get("by_asn", {}).get("buckets", [])
        city_buckets = (
            geo_aggs.get("aggregations", {}).get("by_city", {}).get("buckets", [])
        )
        top_locations = (
            geo_aggs.get("aggregations", {})
            .get("top_locations", {})
            .get("hits", {})
            .get("hits", [])
        )
    except Exception as e:
        l.error("Error fetching geo aggregations from ES: %s", e)
        country_buckets = []
        asn_buckets = []
        city_buckets = []
        top_locations = []

    # Time series aggregation for threat score timeline
    timeline = []
    comparison_count = 0
    current_period_count = 0
    try:
        time_aggs = await es.search(
            index=settings.ELASTICSEARCH_INDEX,
            body={
                "size": 0,
                "query": {"range": {"last_seen": {"gte": "now-7d"}}},
                "aggs": {
                    "timeline": {
                        "date_histogram": {
                            "field": "last_seen",
                            "calendar_interval": "day",
                        },
                        "aggs": {
                            "avg_score": {"avg": {"field": "confidence_score"}},
                            "max_score": {"max": {"field": "confidence_score"}},
                            "count": {"value_count": {"field": "indicator"}},
                            "by_severity": {
                                "filters": {
                                    "filters": {
                                        "critical": {
                                            "range": {"confidence_score": {"gte": 80}}
                                        },
                                        "high": {
                                            "range": {
                                                "confidence_score": {"gte": 60, "lt": 80}
                                            }
                                        },
                                        "medium": {
                                            "range": {
                                                "confidence_score": {"gte": 40, "lt": 60}
                                            }
                                        },
                                        "low": {"range": {"confidence_score": {"lt": 40}}},
                                    }
                                }
                            },
                        },
                    },
                    "comparison": {
                        "filter": {
                            "range": {"last_seen": {"gte": "now-14d", "lt": "now-7d"}}
                        }
                    },
                },
            },
        )

        timeline_buckets = (
            time_aggs.get("aggregations", {}).get("timeline", {}).get("buckets", [])
        )
        current_period_count = sum(b.get("count", {}).get("value", 0) for b in timeline_buckets)
        for b in timeline_buckets:
            severity_counts = b.get("by_severity", {}).get("buckets", {})
            timeline.append(
                {
                    "date": b.get("key_as_string", "")[:10],
                    "timestamp": b.get("key"),
                    "avg_score": round(b.get("avg_score", {}).get("value", 0) or 0, 1),
                    "max_score": round(b.get("max_score", {}).get("value", 0) or 0, 1),
                    "count": b.get("count", {}).get("value", 0),
                    "critical": severity_counts.get("critical", {}).get("doc_count", 0),
                    "high": severity_counts.get("high", {}).get("doc_count", 0),
                    "medium": severity_counts.get("medium", {}).get("doc_count", 0),
                    "low": severity_counts.get("low", {}).get("doc_count", 0),
                }
            )

        comparison_count = (
            time_aggs.get("aggregations", {}).get("comparison", {}).get("doc_count", 0)
        )
    except Exception as e:
        l.error("Error fetching time aggregations from ES: %s", e)

    duration = time.perf_counter() - start
    l.info("Dashboard stats completed in %.4fs", duration)
    return {
        "total_indicators": count_val,
        "latest_indicators": latest_hits,
        "timeline": timeline,
        "comparison": {
            "prior_period_count": comparison_count,
            "current_period_count": current_period_count,
        },
        "events": [
            {
                "type": "feed_added",
                "date": "2026-04-08",
                "description": "URLhaus feed enabled",
            },
            {
                "type": "campaign",
                "date": "2026-04-07",
                "description": "Phishing campaign detected",
            },
        ],
        "geo_summary": {
            "total_mapped": sum(b["doc_count"] for b in country_buckets),
            "countries": [
                {"name": b["key"], "count": b["doc_count"]} for b in country_buckets
            ],
            "asn": [
                {"asn": b["key"], "count": b["doc_count"]}
                for b in asn_buckets
                if b["key"]
            ],
            "cities": [
                {"name": b["key"], "count": b["doc_count"]} for b in city_buckets
            ],
            "top_locations": [
                {
                    "indicator": hit["_source"].get("indicator"),
                    "country": hit["_source"].get("geo", {}).get("country"),
                    "city": hit["_source"].get("geo", {}).get("city"),
                    "lat": hit["_source"].get("geo", {}).get("latitude"),
                    "lng": hit["_source"].get("geo", {}).get("longitude"),
                }
                for hit in top_locations
            ],
        },
    }


@router.get("/feeds/health")
async def get_feed_health(
    pool: Pool = Depends(get_postgres_pool),
):
    """Get health status of all feed sources."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, feed_name, feed_label, status, last_ingested_at, 
               last_success_at, last_error_at, last_error_message, ioc_count,
               ingestion_rate, consecutive_failures, sla_threshold_minutes, 
               is_enabled, updated_at
            FROM feed_health ORDER BY feed_label"""
        )

    from datetime import datetime, timezone

    result = []
    stale_feeds = []
    now = datetime.now(timezone.utc)

    for r in rows:
        status = r["status"]
        last_ingested = r["last_ingested_at"]

        if last_ingested and r["sla_threshold_minutes"]:
            minutes_since_ingestion = (now - last_ingested).total_seconds() / 60
            if minutes_since_ingestion > r["sla_threshold_minutes"]:
                status = "stale"
                stale_feeds.append(
                    {
                        "feed_name": r["feed_name"],
                        "feed_label": r["feed_label"],
                        "last_ingested_at": r["last_ingested_at"].isoformat(),
                        "sla_threshold_minutes": r["sla_threshold_minutes"],
                        "minutes_stale": int(minutes_since_ingestion),
                    }
                )

        result.append(
            {
                "id": r["id"],
                "feed_name": r["feed_name"],
                "feed_label": r["feed_label"],
                "status": status,
                "last_ingested_at": r["last_ingested_at"].isoformat()
                if r["last_ingested_at"]
                else None,
                "last_success_at": r["last_success_at"].isoformat()
                if r["last_success_at"]
                else None,
                "last_error_at": r["last_error_at"].isoformat()
                if r["last_error_at"]
                else None,
                "last_error_message": r["last_error_message"],
                "ioc_count": r["ioc_count"] or 0,
                "ingestion_rate": r["ingestion_rate"] or 0,
                "consecutive_failures": r["consecutive_failures"] or 0,
                "sla_threshold_minutes": r["sla_threshold_minutes"] or 60,
                "is_enabled": r["is_enabled"],
                "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
            }
        )

    response = {
        "feeds": result,
        "stale_alerts": stale_feeds if stale_feeds else None,
        "stale_count": len(stale_feeds),
    }
    return response


@router.post("/feeds/health")
async def update_feed_health(
    update: FeedHealthUpdate,
    pool: Pool = Depends(get_postgres_pool),
):
    """Update feed health after ingestion (called by worker)."""
    async with pool.acquire() as conn:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        if update.success:
            await conn.execute(
                """INSERT INTO feed_health (feed_name, feed_label, status, last_ingested_at, 
                   last_success_at, ioc_count, consecutive_failures, consecutive_successes, updated_at)
                VALUES ($1, $1, 'active', $2, $2, $3, 0, 1, $2)
                ON CONFLICT (feed_name) DO UPDATE SET
                   last_ingested_at = $2,
                   last_success_at = $2,
                   ioc_count = COALESCE(feed_health.ioc_count, 0) + $3,
                   consecutive_failures = 0,
                   consecutive_successes = feed_health.consecutive_successes + 1,
                   status = 'active',
                   updated_at = $2""",
                update.feed_name,
                now,
                update.ioc_count or 0,
            )
        else:
            await conn.execute(
                """INSERT INTO feed_health (feed_name, feed_label, status, last_ingested_at,
                   last_error_at, last_error_message, consecutive_failures, updated_at)
                VALUES ($1, $1, 'error', $2, $2, $3, 1, $2)
                ON CONFLICT (feed_name) DO UPDATE SET
                   last_error_at = $2,
                   last_error_message = $3,
                   consecutive_failures = feed_health.consecutive_failures + 1,
                   consecutive_successes = 0,
                   status = CASE WHEN feed_health.consecutive_failures + 1 >= 3 THEN 'error' ELSE 'active' END,
                   updated_at = $2""",
                update.feed_name,
                now,
                update.error_message or "Unknown error",
            )

        return {"status": "ok", "feed": update.feed_name}


@router.post("/feeds/health/init")
async def init_feeds(
    pool: Pool = Depends(get_postgres_pool),
):
    """Initialize feed health records for all known feeds."""
    FEEDS = [
        ("urlhaus", "URLhaus (Abuse.ch)"),
        ("threatfox", "ThreatFox (Abuse.ch)"),
        ("feodo-tracker", "Feodo Tracker"),
        ("emerging-threats", "Emerging Threats"),
        ("abusech", "Abuse.ch CSV"),
        ("otx", "AlienVault OTX"),
        ("virustotal", "VirusTotal"),
        ("misp", "MISP (Local)"),
        ("openphish", "OpenPhish"),
        ("phishtank", "PhishTank"),
        ("spamhaus", "Spamhaus"),
        ("hybrid_analysis", "Hybrid Analysis"),
    ]

    async with pool.acquire() as conn:
        for name, label in FEEDS:
            await conn.execute(
                """INSERT INTO feed_health (feed_name, feed_label, status)
                VALUES ($1, $2, 'standby')
                ON CONFLICT (feed_name) DO NOTHING""",
                name,
                label,
            )

    return {"status": "ok", "feeds_initialized": len(FEEDS)}


@router.get("/indicators/conflicts", response_model=list[ConflictResponse])
async def get_conflicts(
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: dict = Depends(get_current_token_payload),
) -> list[dict]:
    """Get indicators with conflicting scores from multiple sources."""
    body = {
        "size": 0,
        "query": {"match_all": {}},
        "aggs": {
            "by_indicator": {
                "terms": {"field": "indicator", "size": 100, "min_doc_count": 2},
                "aggs": {
                    "sources": {"terms": {"field": "source", "size": 10}},
                    "score_stats": {"stats": {"field": "confidence_score"}},
                    "type": {"terms": {"field": "type", "size": 1}},
                },
            }
        },
    }

    try:
        response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    except Exception as e:
        import logging
        l = logging.getLogger(__name__)
        l.error("Error fetching conflicts from ES: %s", e)
        return []

    buckets = (
        response.get("aggregations", {}).get("by_indicator", {}).get("buckets", [])
    )

    conflicts = []
    for bucket in buckets:
        source_buckets = bucket.get("sources", {}).get("buckets", [])
        score_stats = bucket.get("score_stats", {})
        type_bucket = bucket.get("type", {}).get("buckets", [])

        if len(source_buckets) < 2:
            continue
        min_score = score_stats.get("min")
        max_score = score_stats.get("max")

        if min_score is None or max_score is None:
            continue

        if max_score - min_score < 10:
            continue

        sources = [s["key"] for s in source_buckets]

        source_details = []
        primary_source_key = None
        if source_buckets:
            primary_source_key = max(source_buckets, key=lambda x: x["doc_count"])["key"]

        for src in source_buckets:
            source_details.append(
                {
                    "source": src["key"],
                    "seen_count": src["doc_count"],
                    "confidence_score": int(
                        (score_stats.get("max") or 0)
                        if src["key"] == primary_source_key
                        else score_stats.get("min") or 50
                    ),
                }
            )

        conflicts.append(
            {
                "indicator": bucket["key"],
                "type": type_bucket[0]["key"] if type_bucket else "unknown",
                "sources": sources,
                "source_details": source_details,
                "min_score": int(min_score),
                "max_score": int(max_score),
            }
        )

    return conflicts


@router.post("/indicators/conflicts/resolve")
async def resolve_conflict(
    data: dict,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    """Resolve a conflict by selecting preferred source/strategy."""
    indicator = data.get("indicator")
    selected_source = data.get("selected_source")
    resolution = data.get("resolution")

    if not indicator:
        raise HTTPException(status_code=400, detail="Indicator required")

    if resolution == "selected_source":
        delete_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"indicator": indicator}},
                        {"bool": {"must_not": [{"term": {"source": selected_source}}]}},
                    ]
                }
            }
        }
        await es.delete_by_query(index=settings.ELASTICSEARCH_INDEX, body=delete_query)

    return {"status": "resolved", "indicator": indicator, "resolution": resolution}


@router.get("/indicators/dedup-config")
async def get_dedup_config(
    pool: Pool = Depends(get_postgres_pool),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    """Get deduplication configuration."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT config FROM dedup_config WHERE id = 1")

    if row:
        return row["config"]

    return {
        "merge_strategy": "highest_score",
        "confidence_weights": {},
        "dedup_enabled": True,
        "conflict_threshold": 10,
    }


@router.post("/indicators/dedup-config")
async def save_dedup_config(
    config: dict,
    pool: Pool = Depends(get_postgres_pool),
    _: dict = Depends(get_current_token_payload),
) -> dict:
    """Save deduplication configuration."""
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO dedup_config (id, config) VALUES (1, $1)
            ON CONFLICT (id) DO UPDATE SET config = $1""",
            config,
        )

    return {"status": "saved", "config": config}


@router.get("/indicators/{indicator_id}", response_model=IndicatorResponse)
async def get_indicator(
    indicator_id: str,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: dict = Depends(get_current_token_payload),
) -> IndicatorResponse:
    index = "neeve-indicators"
    try:
        response = await es.get(index=index, id=indicator_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return serialize(response)
