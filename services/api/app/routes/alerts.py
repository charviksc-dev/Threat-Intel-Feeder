import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from asyncpg import Pool

from ..dependencies import get_postgres_pool
from .auth import get_current_user

router = APIRouter(prefix="/api/v1", tags=["alerts"])


class AlertPayload(BaseModel):
    alert_id: str
    source: str
    severity: str | None = None
    category: str | None = None
    payload: dict


class AlertStatusUpdate(BaseModel):
    status: str
    resolution_type: Optional[str] = None
    reason: Optional[str] = None


class AlertAssign(BaseModel):
    user_id: int


class AlertNoteCreate(BaseModel):
    note: str


async def log_alert_audit(pool: Pool, alert_id: str, action: str, actor_id: int, details: dict = None):
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alert_audit (alert_id, action, actor_id, details) VALUES ($1, $2, $3, $4)",
            alert_id, action, actor_id, json.dumps(details or {})
        )


@router.post("/alerts", status_code=status.HTTP_201_CREATED)
async def ingest_alert(payload: AlertPayload, pool: Pool = Depends(get_postgres_pool), _: object = Depends(get_current_user)) -> dict:
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
async def list_alerts(
    limit: int = 50,
    status_filter: str = Query(None, alias="status"),
    severity: str = Query(None),
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(get_current_user)
) -> List[dict]:
    query = """
        SELECT a.*, u.full_name as assignee_name 
        FROM alerts a 
        LEFT JOIN users u ON a.assigned_to = u.id 
        WHERE 1=1
    """
    params = []
    param_idx = 1

    if status_filter:
        query += f" AND a.status = ${param_idx}"
        params.append(status_filter)
        param_idx += 1
    
    if severity:
        query += f" AND a.severity = ${param_idx}"
        params.append(severity)
        param_idx += 1

    query += f" ORDER BY a.received_at DESC LIMIT ${param_idx}"
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    
    return [dict(row) for row in rows]


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE alerts SET status = 'acknowledged', acknowledged_at = $1, assigned_to = $2 WHERE alert_id = $3",
            datetime.utcnow(), current_user.id, alert_id
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Alert not found")
    
    await log_alert_audit(pool, alert_id, "acknowledged", current_user.id)
    return {"status": "success", "message": "Alert acknowledged"}


@router.post("/alerts/{alert_id}/assign")
async def assign_alert(alert_id: str, payload: AlertAssign, pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE alerts SET assigned_to = $1 WHERE alert_id = $2",
            payload.user_id, alert_id
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Track assignment history
        await conn.execute(
            "INSERT INTO alert_assignments (alert_id, assignee_id, assigned_by) VALUES ($1, $2, $3)",
            alert_id, payload.user_id, current_user.id
        )

    await log_alert_audit(pool, alert_id, "assigned", current_user.id, {"assignee_id": payload.user_id})
    return {"status": "success", "message": "Alert assigned"}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, payload: AlertStatusUpdate, pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)):
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE alerts SET status = $1, resolved_at = $2, resolution_type = $3, false_positive_reason = $4 WHERE alert_id = $5",
            payload.status, datetime.utcnow(), payload.resolution_type, payload.reason, alert_id
        )
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Alert not found")
    
    await log_alert_audit(pool, alert_id, "resolved", current_user.id, {"status": payload.status, "type": payload.resolution_type})
    return {"status": "success", "message": f"Alert {payload.status}"}


@router.post("/alerts/{alert_id}/notes")
async def add_alert_note(alert_id: str, payload: AlertNoteCreate, pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)):
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO alert_notes (alert_id, author_id, note) VALUES ($1, $2, $3)",
            alert_id, current_user.id, payload.note
        )
    return {"status": "success", "message": "Note added"}


@router.get("/alerts/{alert_id}/notes")
async def get_alert_notes(alert_id: str, pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT n.*, u.full_name as author_name FROM alert_notes n JOIN users u ON n.author_id = u.id WHERE alert_id = $1 ORDER BY created_at ASC",
            alert_id
        )
    return [dict(row) for row in rows]


@router.get("/alerts/{alert_id}/audit")
async def get_alert_audit(alert_id: str, pool: Pool = Depends(get_postgres_pool), current_user=Depends(get_current_user)):
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT a.*, u.full_name as actor_name FROM alert_audit a LEFT JOIN users u ON a.actor_id = u.id WHERE alert_id = $1 ORDER BY created_at DESC",
            alert_id
        )
    return [dict(row) for row in rows]
