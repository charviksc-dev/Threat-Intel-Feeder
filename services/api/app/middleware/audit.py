"""Audit Logging Middleware - Tracks all user actions for compliance."""

import json
import logging
from datetime import datetime, timezone
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs all API requests with user context for SOC2/ISO27001 compliance."""

    # Paths to exclude from audit logging
    EXCLUDE_PATHS = {
        "/api/v1/health",
        "/api/v1/auth/providers",
        "/docs",
        "/openapi.json",
        "/redoc",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip excluded paths
        if any(request.url.path.startswith(p) for p in self.EXCLUDE_PATHS):
            return await call_next(request)

        start_time = datetime.now(timezone.utc)

        # Extract user info from token (if present)
        user_email = "anonymous"
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from jose import jwt
                from ..config import settings

                token = auth_header.split(" ")[1]
                payload = jwt.decode(
                    token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
                )
                user_email = payload.get("sub", "unknown")
            except Exception:
                pass

        # Get request body for mutation operations
        body_summary = ""
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                body = await request.body()
                if body:
                    body_json = json.loads(body)
                    # Don't log sensitive fields
                    if isinstance(body_json, dict):
                        body_json.pop("password", None)
                        body_json.pop("hashed_password", None)
                        body_json.pop("access_token", None)
                    body_summary = json.dumps(body_json)[:500]
            except Exception:
                pass

        # Process request
        try:
            response = await call_next(request)
        except Exception as exc:
            response = JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )
            logger.exception("Unhandled API error on %s %s: %s", request.method, request.url.path, exc)

        # Log the audit entry
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        audit_entry = {
            "timestamp": start_time.isoformat(),
            "user": user_email,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.query_params)[:200] if request.query_params else None,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "")[:100],
            "body_summary": body_summary if body_summary else None,
        }

        # Keep high-volume successful reads out of production INFO logs.
        if response.status_code >= 500:
            logger.error("AUDIT: %s", json.dumps(audit_entry))
        elif response.status_code >= 400:
            logger.warning("AUDIT: %s", json.dumps(audit_entry))
        elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
            logger.info("AUDIT: %s", json.dumps(audit_entry))
        else:
            logger.debug("AUDIT: %s", json.dumps(audit_entry))

        return response
