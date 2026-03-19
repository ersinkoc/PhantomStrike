-- Migration: 002_schema_fixes.sql
-- Description: Add missing columns for reports and scheduled_jobs tables
-- Created: 2026-03-19

-- Reports table: add file_path, file_size, status columns used by API handlers
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_path TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT 0;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending';

-- Scheduled jobs table: add description column used by scheduler handler
ALTER TABLE scheduled_jobs ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';

-- Add settings table for runtime configuration updates
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_by  UUID REFERENCES users(id),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Track migration
INSERT INTO schema_migrations (version) VALUES ('002');
