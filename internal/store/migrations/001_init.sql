-- 001_init.sql: Core schema for PhantomStrike

-- Users & Auth
CREATE TABLE IF NOT EXISTS users (
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

-- Organizations (multi-tenant)
CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    plan        TEXT DEFAULT 'free',
    settings    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS org_members (
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'analyst',
    PRIMARY KEY (org_id, user_id)
);

-- Missions
CREATE TABLE IF NOT EXISTS missions (
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

-- Conversations
CREATE TABLE IF NOT EXISTS conversations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID REFERENCES missions(id) ON DELETE CASCADE,
    title       TEXT,
    agent_type  TEXT,
    status      TEXT DEFAULT 'active',
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Messages
CREATE TABLE IF NOT EXISTS messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         TEXT,
    tool_calls      JSONB,
    tool_call_id    TEXT,
    tokens_used     INTEGER,
    model           TEXT,
    provider        TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, created_at);

-- Tool Executions
CREATE TABLE IF NOT EXISTS tool_executions (
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
CREATE INDEX IF NOT EXISTS idx_tool_exec_mission ON tool_executions(mission_id);

-- Artifacts
CREATE TABLE IF NOT EXISTS artifacts (
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

-- Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
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
CREATE INDEX IF NOT EXISTS idx_vulns_mission ON vulnerabilities(mission_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);

-- Attack Chain
CREATE TABLE IF NOT EXISTS attack_chain_nodes (
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

CREATE TABLE IF NOT EXISTS attack_chain_edges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id  UUID REFERENCES missions(id) ON DELETE CASCADE,
    source_id   UUID REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    target_id   UUID REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    edge_type   TEXT NOT NULL,
    label       TEXT,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Scheduled Jobs
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID REFERENCES organizations(id),
    name             TEXT NOT NULL,
    cron_expr        TEXT NOT NULL,
    mission_template JSONB NOT NULL,
    enabled          BOOLEAN DEFAULT true,
    last_run         TIMESTAMPTZ,
    next_run         TIMESTAMPTZ,
    run_count        INTEGER DEFAULT 0,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Reports
CREATE TABLE IF NOT EXISTS reports (
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

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
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
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, created_at DESC);

-- Notification Log
CREATE TABLE IF NOT EXISTS notification_log (
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

-- Tool Registry
CREATE TABLE IF NOT EXISTS tool_registry (
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
