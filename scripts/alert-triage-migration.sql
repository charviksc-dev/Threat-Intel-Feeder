-- Alert Triage Migration Script
-- Run this against your PostgreSQL database to add alert triage functionality

-- Add new columns to alerts table (if they don't exist)
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'new';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to INTEGER;
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
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action_by INTEGER;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS containment_action_at TIMESTAMP WITH TIME ZONE;

-- Create alert_audit table
CREATE TABLE IF NOT EXISTS alert_audit (
    id SERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id INTEGER,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_audit_alert_id ON alert_audit(alert_id);

-- Create alert_assignments table
CREATE TABLE IF NOT EXISTS alert_assignments (
    id SERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    assignee_id INTEGER NOT NULL,
    assigned_by INTEGER NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    unassigned_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_alert_assignments_alert_id ON alert_assignments(alert_id);

-- Create alert_notes table
CREATE TABLE IF NOT EXISTS alert_notes (
    id SERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    author_id INTEGER,
    note TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON alert_notes(alert_id);

-- Update existing alerts to have 'new' status
UPDATE alerts SET status = 'new' WHERE status IS NULL;

-- Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_assigned_to ON alerts(assigned_to);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
