"""Bulk Export - CSV, JSON, STIX export of indicators."""

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse, JSONResponse
from elasticsearch import AsyncElasticsearch

from ..dependencies import get_elasticsearch
from ..config import settings

router = APIRouter(prefix="/api/v1", tags=["export"])


@router.get("/export/csv")
async def export_csv(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float = Query(0),
    limit: int = Query(1000, ge=1, le=10000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as CSV file."""
    indicators = await _fetch_indicators(es, source, severity, min_score, limit)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "indicator",
            "type",
            "source",
            "confidence_score",
            "severity",
            "threat_types",
            "tags",
            "first_seen",
            "country",
        ]
    )

    for ind in indicators:
        writer.writerow(
            [
                ind.get("indicator", ""),
                ind.get("type", ""),
                ind.get("source", ""),
                ind.get("confidence_score", ""),
                ind.get("severity", ""),
                "|".join(ind.get("threat_types", [])),
                "|".join(ind.get("tags", [])),
                ind.get("first_seen", ""),
                (ind.get("geo") or {}).get("country", ""),
            ]
        )

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=neeve-indicators-{datetime.now().strftime('%Y%m%d')}.csv"
        },
    )


@router.get("/export/json")
async def export_json(
    source: str | None = Query(None),
    severity: str | None = Query(None),
    min_score: float = Query(0),
    limit: int = Query(1000, ge=1, le=10000),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Export indicators as JSON file."""
    indicators = await _fetch_indicators(es, source, severity, min_score, limit)

    return JSONResponse(
        content={
            "exported_at": datetime.utcnow().isoformat(),
            "count": len(indicators),
            "indicators": indicators,
        },
        headers={
            "Content-Disposition": f"attachment; filename=neeve-indicators-{datetime.now().strftime('%Y%m%d')}.json"
        },
    )


@router.get("/export/ioc-list")
async def export_ioc_list(
    format: str = Query("plain", description="plain, csv_ips, csv_domains"),
    source: str | None = Query(None),
    min_score: float = Query(40),
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Simple IOC list export for quick use."""
    indicators = await _fetch_indicators(es, source, None, min_score, 10000)

    if format == "csv_ips":
        ips = [i["indicator"] for i in indicators if i.get("type") in ("ipv4", "ipv6")]
        return StreamingResponse(
            io.BytesIO("\n".join(ips).encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=ips.csv"},
        )
    elif format == "csv_domains":
        domains = [i["indicator"] for i in indicators if i.get("type") == "domain"]
        return StreamingResponse(
            io.BytesIO("\n".join(domains).encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=domains.csv"},
        )
    else:
        lines = [f"{i['indicator']}" for i in indicators]
        return StreamingResponse(
            io.BytesIO("\n".join(lines).encode()),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=iocs.txt"},
        )


@router.post("/bulk/tag")
async def bulk_tag(
    indicator_ids: list[str],
    tags: list[str],
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    pool=Depends(lambda: None),  # Placeholder for audit
):
    """Add tags to multiple indicators at once."""
    updated = 0
    for iid in indicator_ids:
        try:
            doc = await es.get(index=settings.ELASTICSEARCH_INDEX, id=iid)
            existing_tags = doc["_source"].get("tags", [])
            new_tags = list(set(existing_tags + tags))
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=iid,
                body={"doc": {"tags": new_tags}},
            )
            updated += 1
        except Exception:
            pass

    return {"updated": updated, "total": len(indicator_ids)}


@router.post("/bulk/block")
async def bulk_block(
    indicator_ids: list[str],
    es: AsyncElasticsearch = Depends(get_elasticsearch),
):
    """Mark multiple indicators as blocked and add to blocklist."""
    blocked = 0
    for iid in indicator_ids:
        try:
            await es.update(
                index=settings.ELASTICSEARCH_INDEX,
                id=iid,
                body={"doc": {"tags": ["blocked", "firewall-added"], "blocked": True}},
            )
            blocked += 1
        except Exception:
            pass

    return {"blocked": blocked, "total": len(indicator_ids)}


async def _fetch_indicators(es, source, severity, min_score, limit):
    """Helper to fetch indicators with filters."""
    filters = [{"range": {"confidence_score": {"gte": min_score}}}]
    if source:
        filters.append({"term": {"source": source}})
    if severity:
        filters.append({"term": {"severity": severity}})

    body = {
        "query": {"bool": {"filter": filters}},
        "size": limit,
        "sort": [{"confidence_score": "desc"}],
    }

    response = await es.search(index=settings.ELASTICSEARCH_INDEX, body=body)
    return [hit["_source"] for hit in response["hits"]["hits"]]
