import logging

from asyncpg import Pool

logger = logging.getLogger(__name__)


USER_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    hashed_password TEXT,
    role TEXT NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    provider TEXT NOT NULL DEFAULT 'local',
    provider_id TEXT,
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);
"""

ALERT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,
    severity TEXT,
    category TEXT,
    payload JSONB,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
"""


async def ensure_metadata_tables(pool: Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(USER_TABLE_SQL)
        await conn.execute(ALERT_TABLE_SQL)

        # Add new columns if they don't exist (migration for existing tables)
        migrations = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'local'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_id TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL",
        ]
        for sql in migrations:
            try:
                await conn.execute(sql)
            except Exception:
                pass

        logger.info("Metadata tables created or already exist")
