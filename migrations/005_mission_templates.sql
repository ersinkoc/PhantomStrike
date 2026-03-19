-- Migration: 005_mission_templates.sql
-- Description: Mission templates table for reusable mission configurations
-- Created: 2026-03-19

CREATE TABLE IF NOT EXISTS mission_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    target      JSONB NOT NULL DEFAULT '{}',
    mode        TEXT DEFAULT 'autonomous',
    depth       TEXT DEFAULT 'standard',
    phases      TEXT[] DEFAULT '{}',
    role        TEXT DEFAULT '',
    config      JSONB DEFAULT '{}',
    is_builtin  BOOLEAN DEFAULT false,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mission_templates_name ON mission_templates(name);
CREATE INDEX IF NOT EXISTS idx_mission_templates_builtin ON mission_templates(is_builtin);

CREATE TRIGGER update_mission_templates_updated_at BEFORE UPDATE ON mission_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

INSERT INTO schema_migrations (version) VALUES ('005');
