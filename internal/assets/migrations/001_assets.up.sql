-- Assets and Discovery Tables

CREATE TABLE IF NOT EXISTS asset_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('domain', 'ip_range', 'cidr', 'wildcard', 'url', 'mobile_app')),
    value TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id UUID REFERENCES asset_scopes(id) ON DELETE SET NULL,
    mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    asset_type TEXT NOT NULL CHECK (asset_type IN (
        'domain', 'subdomain', 'ip', 'service', 'port',
        'endpoint', 'technology', 'certificate', 'cloud_resource'
    )),
    value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'removed')),

    -- Enrichment data
    data JSONB,

    -- Source tracking
    sources TEXT[] DEFAULT '{}',
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scan_count INTEGER DEFAULT 0,

    -- Change tracking
    previous_data JSONB,
    change_type TEXT CHECK (change_type IN ('new', 'modified', 'removed', 'unchanged')),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(mission_id, asset_type, value)
);

CREATE TABLE IF NOT EXISTS asset_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL CHECK (relationship_type IN (
        'resolves_to', 'hosts', 'runs', 'serves',
        'depends_on', 'part_of', 'associated_with'
    )),
    metadata JSONB,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(source_asset_id, target_asset_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS asset_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT,
    banner TEXT,
    version TEXT,

    -- Service fingerprinting
    cpe TEXT,

    -- SSL/TLS info
    tls_version TEXT,
    cipher_suite TEXT,
    certificate_id UUID,

    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'filtered', 'closed')),

    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS asset_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- Certificate details
    subject_common_name TEXT,
    subject_organization TEXT,
    issuer_common_name TEXT,
    issuer_organization TEXT,

    -- Validity
    not_before TIMESTAMP WITH TIME ZONE,
    not_after TIMESTAMP WITH TIME ZONE,
    is_valid BOOLEAN DEFAULT true,

    -- Fingerprints
    serial_number TEXT,
    fingerprint_sha256 TEXT,
    fingerprint_sha1 TEXT,

    -- SANs
    subject_alt_names TEXT[],

    -- Chain info
    chain_valid BOOLEAN,
    chain_depth INTEGER,

    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_soon BOOLEAN GENERATED ALWAYS AS (
        not_after < NOW() + INTERVAL '30 days' AND not_after > NOW()
    ) STORED,
    expired BOOLEAN GENERATED ALWAYS AS (not_after < NOW()) STORED
);

CREATE TABLE IF NOT EXISTS asset_technologies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT,
    version TEXT,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    detection_method TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(asset_id, name)
);

CREATE TABLE IF NOT EXISTS asset_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    change_type TEXT NOT NULL CHECK (change_type IN ('added', 'removed', 'modified', 'status_changed')),
    field_name TEXT,
    old_value JSONB,
    new_value JSONB,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notification_sent BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mission_id UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    scope_id UUID REFERENCES asset_scopes(id) ON DELETE CASCADE,

    job_type TEXT NOT NULL CHECK (job_type IN (
        'subdomain_enum', 'port_scan', 'service_enum',
        'tech_detect', 'screenshot', 'certificate_check'
    )),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),

    -- Configuration
    config JSONB,

    -- Progress tracking
    total_targets INTEGER DEFAULT 0,
    processed_targets INTEGER DEFAULT 0,
    found_assets INTEGER DEFAULT 0,

    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_assets_mission ON assets(mission_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_change_type ON assets(change_type);
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
CREATE INDEX IF NOT EXISTS idx_assets_first_seen ON assets(first_seen);

CREATE INDEX IF NOT EXISTS idx_asset_changes_mission ON asset_changes(mission_id);
CREATE INDEX IF NOT EXISTS idx_asset_changes_detected ON asset_changes(detected_at);
CREATE INDEX IF NOT EXISTS idx_asset_changes_notification ON asset_changes(notification_sent);

CREATE INDEX IF NOT EXISTS idx_certificates_expires ON asset_certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_expires_soon ON asset_certificates(expires_soon) WHERE expires_soon = true;

CREATE INDEX IF NOT EXISTS idx_relationships_source ON asset_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON asset_relationships(target_asset_id);

CREATE INDEX IF NOT EXISTS idx_services_asset ON asset_services(asset_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON asset_services(port);

CREATE INDEX IF NOT EXISTS idx_technologies_name ON asset_technologies(name);

-- GIN indexes for JSONB queries
CREATE INDEX IF NOT EXISTS idx_assets_data ON assets USING GIN(data);
CREATE INDEX IF NOT EXISTS idx_assets_sources ON assets USING GIN(sources);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_asset_scopes_updated_at BEFORE UPDATE ON asset_scopes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
