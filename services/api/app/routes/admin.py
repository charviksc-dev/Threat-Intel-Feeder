"""Admin & RBAC Routes - User management, roles, audit logs."""

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from asyncpg import Pool

from ..dependencies import get_postgres_pool
from ..schemas import User, UserRole
from ..routes.auth import get_current_user
from ..services.auth import create_user, get_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["admin"])


def require_admin(current_user=Depends(get_current_user)):
    """Dependency that requires admin role."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@router.get("/admin/users")
async def list_users(
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(require_admin),
):
    """List all users (admin only)."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, email, full_name, role, is_active, provider, created_at, last_login FROM users ORDER BY created_at DESC"
        )
    return [
        {
            "id": r["id"],
            "email": r["email"],
            "full_name": r["full_name"],
            "role": r["role"],
            "is_active": r["is_active"],
            "provider": r["provider"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "last_login": r["last_login"].isoformat() if r["last_login"] else None,
        }
        for r in rows
    ]


@router.post("/admin/users")
async def create_new_user(
    email: str,
    password: str,
    full_name: str,
    role: str = "analyst",
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(require_admin),
):
    """Create a new user (admin only)."""
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(
            status_code=400, detail="Role must be admin, analyst, or viewer"
        )

    user = await create_user(pool, email, full_name, password, role)
    return {
        "message": "User created",
        "user": {"id": user.id, "email": user.email, "role": user.role},
    }


@router.put("/admin/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    role: str,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(require_admin),
):
    """Update user role (admin only)."""
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(
            status_code=400, detail="Role must be admin, analyst, or viewer"
        )

    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE users SET role = $1 WHERE id = $2",
            role,
            user_id,
        )

    return {"message": "Role updated", "user_id": user_id, "role": role}


@router.put("/admin/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(require_admin),
):
    """Deactivate a user (admin only)."""
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET is_active = false WHERE id = $1", user_id)
    return {"message": "User deactivated", "user_id": user_id}


@router.get("/admin/audit-logs")
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    user: str | None = Query(None),
    method: str | None = Query(None),
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(require_admin),
):
    """Get audit logs from PostgreSQL (admin only)."""
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    param_idx = 1

    if user:
        query += f" AND user_email = ${param_idx}"
        params.append(user)
        param_idx += 1
    if method:
        query += f" AND method = ${param_idx}"
        params.append(method.upper())
        param_idx += 1

    query += f" ORDER BY timestamp DESC LIMIT ${param_idx}"
    params.append(limit)

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"].isoformat() if r["timestamp"] else None,
                "user_email": r["user_email"],
                "method": r["method"],
                "path": r["path"],
                "status_code": r["status_code"],
                "response_time_ms": r["response_time_ms"],
                "ip_address": r["ip_address"],
            }
            for r in rows
        ]
    except Exception as e:
        logger.warning("Audit log query failed: %s", e)
        return {
            "message": "Audit logs table not yet initialized. Restart the API to create it.",
            "error": str(e),
        }


@router.get("/admin/system-health")
async def system_health(
    pool: Pool = Depends(get_postgres_pool),
    current_user=Depends(require_admin),
):
    """System health check (admin only)."""
    from ..db import create_elasticsearch_client
    from ..config import settings

    health = {"status": "healthy", "services": {}}

    # Check PostgreSQL
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        health["services"]["postgresql"] = {"status": "up"}
    except Exception as e:
        health["services"]["postgresql"] = {"status": "down", "error": str(e)}
        health["status"] = "degraded"

    # Check Elasticsearch
    try:
        es = await create_elasticsearch_client()
        info = await es.info()
        health["services"]["elasticsearch"] = {
            "status": "up",
            "version": info.get("version", {}).get("number"),
        }
        await es.close()
    except Exception as e:
        health["services"]["elasticsearch"] = {"status": "down", "error": str(e)}
        health["status"] = "degraded"

    # Check Redis
    try:
        import redis.asyncio as aioredis

        redis = aioredis.from_url(settings.REDIS_URL)
        await redis.ping()
        health["services"]["redis"] = {"status": "up"}
        await redis.close()
    except Exception as e:
        health["services"]["redis"] = {"status": "down", "error": str(e)}
        health["status"] = "degraded"

    return health
