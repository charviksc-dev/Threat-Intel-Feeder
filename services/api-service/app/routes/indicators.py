from typing import List

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1", tags=["indicators"])


def _serialize_indicator(document: dict) -> dict:
    if not document:
        return {}
    document["id"] = str(document.pop("_id"))
    return document


@router.get("/indicators")
async def list_indicators(
    request: Request,
    source: str | None = None,
    skip: int = 0,
    limit: int = 50,
) -> List[dict]:
    db = request.app.state.db
    query = {}
    if source:
        query["source"] = source
    cursor = db.indicators.find(query).skip(skip).limit(limit)
    documents = await cursor.to_list(length=limit)
    return [_serialize_indicator(doc) for doc in documents]


@router.get("/sources")
async def list_sources(request: Request) -> list[str]:
    db = request.app.state.db
    sources = await db.indicators.distinct("source")
    return [source for source in sources if source]


@router.get("/indicators/{indicator_id}")
async def get_indicator(request: Request, indicator_id: str) -> dict:
    db = request.app.state.db
    try:
        document = await db.indicators.find_one({"_id": ObjectId(indicator_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid indicator id")
    if not document:
        raise HTTPException(status_code=404, detail="Indicator not found")

    return _serialize_indicator(document)


@router.get("/stats")
async def get_stats(request: Request) -> dict:
    db = request.app.state.db
    total = await db.indicators.count_documents({})
    latest = await db.indicators.find().sort("last_seen", -1).limit(5).to_list(length=5)
    return {
        "total_indicators": total,
        "latest_indicators": [_serialize_indicator(item) for item in latest],
    }
