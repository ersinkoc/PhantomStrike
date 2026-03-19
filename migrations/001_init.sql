-- Migration: 001_init.sql
-- Description: Initial database schema for PhantomStrike
-- Created: 2026-03-19

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- =====================================================
-- USERS & AUTHENTICATION
-- =====================================================

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'analyst',
    api_key     TEXT UNIQUE,
    avatar_url  TEXT,
    settings    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_api_key ON users(api_key);

-- =====================================================
-- ORGANIZATIONS (Multi-tenant)
-- =====================================================

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    plan        TEXT DEFAULT 'free',
    settings    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE org_members (
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'analyst',
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX idx_org_members_org ON org_members(org_id);
CREATE INDEX idx_org_members_user ON org_members(user_id);

-- =====================================================
-- MISSIONS
-- =====================================================

CREATE TABLE missions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    created_by      UUID REFERENCES users(id),
    name            TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'created',
    mode            TEXT NOT NULL DEFAULT 'autonomous',
    depth           TEXT NOT NULL DEFAULT 'standard',
    target          JSONB NOT NULL,
    config          JSONB DEFAULT '{}',
    phases          TEXT[] DEFAULT '{}',
    current_phase   TEXT,
    progress        INTEGER DEFAULT 0,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_missions_org ON missions(org_id);
CREATE INDEX idx_missions_status ON missions(status);
CREATE INDEX idx_missions_created_by ON missions(created_by);

-- =====================================================
-- CONVERSATIONS
-- =====================================================

CREATE TABLE conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id      UUID REFERENCES missions(id) ON DELETE CASCADE,
    title           TEXT,
    agent_type      TEXT,
    status          TEXT DEFAULT 'active',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_conversations_mission ON conversations(mission_id);

-- =====================================================
-- MESSAGES
-- =====================================================

CREATE TABLE messages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id     UUID REFERENCES conversations(id) ON DELETE CASCADE,
    role                TEXT NOT NULL,
    content             TEXT,
    tool_calls          JSONB,
    tool_call_id        TEXT,
    tokens_used         INTEGER,
    model               TEXT,
    provider            TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_messages_conv ON messages(conversation_id, created_at DESC);

-- =====================================================
-- TOOL EXECUTIONS
-- =====================================================

CREATE TABLE tool_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id),
    mission_id      UUID REFERENCES missions(id),
    tool_name       TEXT NOT NULL,
    parameters      JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    execution_mode  TEXT DEFAULT 'docker',
    container_id    TEXT,
    stdout          TEXT,
    stderr          TEXT,
    exit_code       INTEGER,
    artifact_id     UUID,
    duration_ms     INTEGER,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_tool_exec_mission ON tool_executions(mission_id);
CREATE INDEX idx_tool_exec_conv ON tool_executions(conversation_id);
CREATE INDEX idx_tool_exec_status ON tool_executions(status);

-- =====================================================
-- ARTIFACTS
-- =====================================================

CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID REFERENCES missions(id),
    name        TEXT NOT NULL,
    mime_type   TEXT NOT NULL,
    size_bytes  BIGINT,
    storage_key TEXT NOT NULL,
    checksum    TEXT,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_artifacts_mission ON artifacts(mission_id);

-- =====================================================
-- VULNERABILITIES
-- =====================================================

CREATE TABLE vulnerabilities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id          UUID REFERENCES missions(id),
    conversation_id     UUID REFERENCES conversations(id),
    tool_execution_id   UUID REFERENCES tool_executions(id),
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL,
    cvss_score          NUMERIC(3,1),
    cvss_vector         TEXT,
    status              TEXT DEFAULT 'open',
    target              TEXT,
    affected_component  TEXT,
    evidence            TEXT,
    remediation         TEXT,
    cve_ids             TEXT[],
    cwe_id              TEXT,
    tags                TEXT[],
    found_by            TEXT,
    verified_by         TEXT,
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vulns_mission ON vulnerabilities(mission_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_vulns_cve ON vulnerabilities USING GIN(cve_ids);

-- =====================================================
-- ATTACK CHAIN (Graph)
-- =====================================================

CREATE TABLE attack_chain_nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID REFERENCES missions(id) ON DELETE CASCADE,
    node_type   TEXT NOT NULL,
    label       TEXT NOT NULL,
    data        JSONB DEFAULT '{}',
    severity    TEXT,
    phase       TEXT,
    position_x  NUMERIC,
    position_y  NUMERIC,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_chain_nodes_mission ON attack_chain_nodes(mission_id);

CREATE TABLE attack_chain_edges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID REFERENCES missions(id) ON DELETE CASCADE,
    source_id   UUID REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    target_id   UUID REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    edge_type   TEXT NOT NULL,
    label       TEXT,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_chain_edges_mission ON attack_chain_edges(mission_id);
CREATE INDEX idx_chain_edges_source ON attack_chain_edges(source_id);
CREATE INDEX idx_chain_edges_target ON attack_chain_edges(target_id);

-- =====================================================
-- KNOWLEDGE BASE (pgvector)
-- =====================================================

CREATE TABLE knowledge_items (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    source_file TEXT,
    chunk_index INTEGER DEFAULT 0,
    embedding   vector(3072),
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_knowledge_embedding ON knowledge_items
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX idx_knowledge_category ON knowledge_items(category);
CREATE INDEX idx_knowledge_fulltext ON knowledge_items
    USING GIN (to_tsvector('english', title || ' ' || content));

-- =====================================================
-- SCHEDULED JOBS
-- =====================================================

CREATE TABLE scheduled_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    name            TEXT NOT NULL,
    cron_expr       TEXT NOT NULL,
    mission_template JSONB NOT NULL,
    enabled         BOOLEAN DEFAULT true,
    last_run        TIMESTAMPTZ,
    next_run        TIMESTAMPTZ,
    run_count       INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scheduled_jobs_org ON scheduled_jobs(org_id);
CREATE INDEX idx_scheduled_jobs_next ON scheduled_jobs(next_run) WHERE enabled = true;

-- =====================================================
-- REPORTS
-- =====================================================

CREATE TABLE reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID REFERENCES missions(id),
    title       TEXT NOT NULL,
    format      TEXT NOT NULL,
    artifact_id UUID REFERENCES artifacts(id),
    template    TEXT DEFAULT 'standard',
    generated_by TEXT,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_reports_mission ON reports(mission_id);

-- =====================================================
-- AUDIT LOG
-- =====================================================

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID,
    user_id     UUID,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    resource_id UUID,
    details     JSONB DEFAULT '{}',
    ip_address  INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_log(org_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource, resource_id);

-- =====================================================
-- NOTIFICATION LOG
-- =====================================================

CREATE TABLE notification_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID,
    channel     TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL,
    status      TEXT DEFAULT 'pending',
    error       TEXT,
    sent_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_notif_mission ON notification_log(mission_id);
CREATE INDEX idx_notif_status ON notification_log(status);

-- =====================================================
-- TOOL REGISTRY
-- =====================================================

CREATE TABLE tool_registry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT UNIQUE NOT NULL,
    category        TEXT NOT NULL,
    definition      JSONB NOT NULL,
    source          TEXT DEFAULT 'builtin',
    enabled         BOOLEAN DEFAULT true,
    install_count   INTEGER DEFAULT 0,
    avg_exec_time   INTEGER,
    success_rate    NUMERIC(5,2),
    last_used       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_tool_registry_cat ON tool_registry(category);
CREATE INDEX idx_tool_registry_enabled ON tool_registry(enabled);

-- =====================================================
-- FUNCTIONS & TRIGGERS
-- =====================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_missions_updated_at BEFORE UPDATE ON missions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversations_updated_at BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_knowledge_items_updated_at BEFORE UPDATE ON knowledge_items
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tool_registry_updated_at BEFORE UPDATE ON tool_registry
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Migration tracking
CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO schema_migrations (version) VALUES ('001');
