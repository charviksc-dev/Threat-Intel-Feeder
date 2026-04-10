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

ALTER_ALERT_TABLE_SQL = """
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'new';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to INTEGER REFERENCES users(id);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution_type TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS false_positive_reason TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS priority_override TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity_override TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactics TEXT[];
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[];
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensor_source TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensor_rule_id TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_hostname TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_owner TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_criticality TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_network_zone TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS campaign_tag TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS related_alert_ids TEXT[];
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_status TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action_by INTEGER REFERENCES users(id);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action_at TIMESTAMP WITH TIME ZONE;
"""

ALERT_AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alert_audit (
    id SERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id INTEGER,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_audit_alert_id ON alert_audit(alert_id);
"""

ALERT_ASSIGNMENT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alert_assignments (
    id SERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    assignee_id INTEGER NOT NULL,
    assigned_by INTEGER NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    unassigned_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_alert_assignments_alert_id ON alert_assignments(alert_id);
"""

ALERT_NOTES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alert_notes (
    id SERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    author_id INTEGER REFERENCES users(id),
    note TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON alert_notes(alert_id);
"""

FEED_HEALTH_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS feed_health (
    id SERIAL PRIMARY KEY,
    feed_name TEXT UNIQUE NOT NULL,
    feed_label TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_ingested_at TIMESTAMP WITH TIME ZONE,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_error_at TIMESTAMP WITH TIME ZONE,
    last_error_message TEXT,
    ioc_count BIGINT DEFAULT 0,
    ingestion_rate INTEGER DEFAULT 0,
    consecutive_failures INTEGER DEFAULT 0,
    consecutive_successes INTEGER DEFAULT 0,
    sla_threshold_minutes INTEGER DEFAULT 60,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feed_health_status ON feed_health(status);
CREATE INDEX IF NOT EXISTS idx_feed_health_last_ingested ON feed_health(last_ingested_at);
"""


async def ensure_metadata_tables(pool: Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(USER_TABLE_SQL)
        await conn.execute(ALERT_TABLE_SQL)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at DESC);"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status_severity_received ON alerts(status, severity, received_at DESC);"
        )
        await conn.execute(ALERT_AUDIT_TABLE_SQL)
        await conn.execute(ALERT_ASSIGNMENT_TABLE_SQL)
        await conn.execute(ALERT_NOTES_TABLE_SQL)
        await conn.execute(FEED_HEALTH_TABLE_SQL)

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

        alert_migrations = [
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'new'",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to INTEGER",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution_type TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS false_positive_reason TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS priority_override TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity_override TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactics TEXT[]",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[]",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensor_source TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensor_rule_id TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_hostname TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_owner TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_criticality TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_network_zone TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS campaign_tag TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS related_alert_ids TEXT[]",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_status TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action TEXT",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action_by INTEGER",
            "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action_at TIMESTAMP WITH TIME ZONE",
        ]

        for sql in alert_migrations:
            try:
                await conn.execute(sql)
            except Exception:
                pass

        logger.info("Metadata tables created or already exist")
