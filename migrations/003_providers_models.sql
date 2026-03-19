-- Migration: 003_providers_models.sql
-- Description: Provider and model management tables for dynamic AI provider configuration
-- Created: 2026-03-19

-- AI Providers (user-configured, synced from models.dev or manual)
CREATE TABLE IF NOT EXISTS ai_providers (
    id              TEXT PRIMARY KEY,                    -- e.g. "anthropic", "openai", "groq"
    name            TEXT NOT NULL,                       -- Display name
    api_base_url    TEXT NOT NULL,                       -- API endpoint
    api_key         TEXT DEFAULT '',                     -- Encrypted API key
    env_var         TEXT DEFAULT '',                     -- Environment variable name (e.g. ANTHROPIC_API_KEY)
    sdk_type        TEXT DEFAULT 'openai_compatible',    -- "anthropic", "openai", "openai_compatible", "ollama"
    doc_url         TEXT DEFAULT '',                     -- Documentation URL
    is_enabled      BOOLEAN DEFAULT false,               -- User has enabled & configured this provider
    is_configured   BOOLEAN DEFAULT false,               -- API key is set
    is_local        BOOLEAN DEFAULT false,               -- Local provider (e.g. Ollama)
    priority        INTEGER DEFAULT 100,                 -- For fallback chain ordering (lower = higher priority)
    settings        JSONB DEFAULT '{}',                  -- Extra provider-specific settings
    synced_from     TEXT DEFAULT '',                     -- "models.dev" or "manual"
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- AI Models (available models per provider)
CREATE TABLE IF NOT EXISTS ai_models (
    id              TEXT NOT NULL,                       -- Model ID (e.g. "claude-sonnet-4-20250514")
    provider_id     TEXT NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,                       -- Display name
    family          TEXT DEFAULT '',                     -- Model family (e.g. "claude", "gpt", "llama")

    -- Capabilities
    tool_call       BOOLEAN DEFAULT false,
    reasoning       BOOLEAN DEFAULT false,
    attachment      BOOLEAN DEFAULT false,
    temperature     BOOLEAN DEFAULT true,

    -- Modalities
    input_modalities  TEXT[] DEFAULT '{text}',           -- text, image, video, audio, pdf
    output_modalities TEXT[] DEFAULT '{text}',           -- text, image

    -- Limits
    context_window  INTEGER DEFAULT 0,
    max_output      INTEGER DEFAULT 0,

    -- Cost (per million tokens, USD)
    cost_input      NUMERIC(10,4) DEFAULT 0,
    cost_output     NUMERIC(10,4) DEFAULT 0,
    cost_cache_read NUMERIC(10,4) DEFAULT 0,
    cost_cache_write NUMERIC(10,4) DEFAULT 0,

    -- Metadata
    knowledge_cutoff TEXT DEFAULT '',                    -- e.g. "2025-04"
    release_date    DATE,
    open_weights    BOOLEAN DEFAULT false,
    is_enabled      BOOLEAN DEFAULT true,

    synced_from     TEXT DEFAULT '',
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (id, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_models_provider ON ai_models(provider_id);
CREATE INDEX IF NOT EXISTS idx_ai_models_family ON ai_models(family);
CREATE INDEX IF NOT EXISTS idx_ai_models_tool_call ON ai_models(tool_call) WHERE tool_call = true;

-- Default provider preferences (which provider/model for each role)
CREATE TABLE IF NOT EXISTS ai_preferences (
    key             TEXT PRIMARY KEY,                    -- "default", "planner", "executor", "reviewer", "embedding"
    provider_id     TEXT NOT NULL REFERENCES ai_providers(id),
    model_id        TEXT NOT NULL,
    settings        JSONB DEFAULT '{}',                  -- max_tokens, temperature, etc.
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Setup state tracking
CREATE TABLE IF NOT EXISTS setup_state (
    key             TEXT PRIMARY KEY,
    value           JSONB NOT NULL,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO setup_state (key, value) VALUES ('setup_completed', 'false') ON CONFLICT DO NOTHING;
INSERT INTO setup_state (key, value) VALUES ('models_last_synced', 'null') ON CONFLICT DO NOTHING;

-- Track migration
INSERT INTO schema_migrations (version) VALUES ('003');
