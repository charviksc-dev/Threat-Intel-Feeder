"""Neev Threat Intelligence Platform — API Gateway (Production)"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import settings
from .db import create_postgres_pool, create_elasticsearch_client
from .db_schema import ensure_metadata_tables
from .routes import indicators, auth, siem, stix, export, admin, search, alerts
from .middleware.audit import AuditLogMiddleware

logging.basicConfig(
    level=logging.INFO if settings.APP_ENV == "production" else logging.DEBUG,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("neev.api")

# Rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan context manager — replaces deprecated on_event handlers."""
    logger.info("Neev TIP API starting up (env=%s)...", settings.APP_ENV)
    app.state.postgres = await create_postgres_pool()
    app.state.es = await create_elasticsearch_client()

    # Redis connection
    import redis.asyncio as aioredis

    app.state.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

    # Create audit_logs table if not exists
    try:
        async with app.state.postgres.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ DEFAULT NOW(),
                    user_email VARCHAR(255),
                    method VARCHAR(10),
                    path VARCHAR(500),
                    status_code INTEGER,
                    response_time_ms FLOAT,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    request_body TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_email);
            """)
        logger.info("Audit log table verified")
    except Exception as e:
        logger.warning("Could not create audit_logs table: %s", e)

    logger.info("Database connections established")

    # Ensure database tables exist
    try:
        await ensure_metadata_tables(app.state.postgres)
        logger.info("Database schema verified")
    except Exception as e:
        logger.warning("Could not verify database schema: %s", e)

    yield
    logger.info("Neev TIP API shutting down...")
    if hasattr(app.state, "postgres") and app.state.postgres:
        await app.state.postgres.close()
    if hasattr(app.state, "es") and app.state.es:
        await app.state.es.close()
    if hasattr(app.state, "redis") and app.state.redis:
        await app.state.redis.close()


app = FastAPI(
    title="Neev TIP",
    description="Threat Intelligence Platform API — Production",
    version="2.1.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware (CORS must be added LAST so it runs FIRST in the chain)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS.split(",")
    if settings.ALLOWED_ORIGINS
    else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(auth.router)
app.include_router(indicators.router)
app.include_router(siem.router)
app.include_router(stix.router)
app.include_router(export.router)
app.include_router(admin.router)
app.include_router(search.router)
app.include_router(alerts.router)


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "version": "2.1.0", "env": settings.APP_ENV}
