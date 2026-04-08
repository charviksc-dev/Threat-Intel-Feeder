from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..dependencies import get_postgres_pool
from .auth import get_current_user

router = APIRouter(prefix="/api/v1", tags=["alerts"])


class AlertPayload(BaseModel):
    alert_id: str
    source: str
    severity: str | None = None
    category: str | None = None
    payload: dict


@router.post("/alerts", status_code=status.HTTP_201_CREATED)
async def ingest_alert(payload: AlertPayload, pool=Depends(get_postgres_pool), _: object = Depends(get_current_user)) -> dict:
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alerts (alert_id, source, severity, category, payload, received_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (alert_id) DO NOTHING",
            payload.alert_id,
            payload.source,
            payload.severity,
            payload.category,
            payload.payload,
            datetime.utcnow(),
        )
    return {"status": "accepted", "alert_id": payload.alert_id}


@router.get("/alerts")
async def list_alerts(limit: int = 50, pool=Depends(get_postgres_pool), _: object = Depends(get_current_user)) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT alert_id, source, severity, category, payload, received_at FROM alerts ORDER BY received_at DESC LIMIT $1", limit)
    return [dict(row) for row in rows]
