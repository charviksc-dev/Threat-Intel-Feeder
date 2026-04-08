from fastapi import APIRouter, Depends, HTTPException, Query
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import NotFoundError

from ..dependencies import get_elasticsearch
from ..schemas import IndicatorResponse, IOCType
from ..config import settings
from .auth import get_current_user

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
    _: object = Depends(get_current_user),
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


@router.get("/indicators/{indicator_id}", response_model=IndicatorResponse)
async def get_indicator(
    indicator_id: str,
    es: AsyncElasticsearch = Depends(get_elasticsearch),
    _: object = Depends(get_current_user),
) -> IndicatorResponse:
    index = "neeve-indicators"
    try:
        response = await es.get(index=index, id=indicator_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return serialize(response)


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
    _: object = Depends(get_current_user),
) -> dict:
    count = await es.count(index=settings.ELASTICSEARCH_INDEX)
    latest = await es.search(
        index=settings.ELASTICSEARCH_INDEX,
        body={
            "query": {"match_all": {}},
            "sort": [{"last_seen": {"order": "desc"}}],
            "size": 5,
        },
    )
    return {
        "total_indicators": count.get("count", 0),
        "latest_indicators": [serialize(hit) for hit in latest["hits"]["hits"]],
    }
