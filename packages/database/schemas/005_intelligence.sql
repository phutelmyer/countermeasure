-- 005_intelligence.sql
-- Threat intelligence collection and management

-- Create intelligence table
CREATE TABLE IF NOT EXISTS intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    source VARCHAR(255),
    url VARCHAR(2048),
    content TEXT,
    summary TEXT,
    iocs JSONB DEFAULT '[]', -- Indicators of Compromise
    mitre_techniques TEXT[] DEFAULT '{}',
    threat_actors TEXT[] DEFAULT '{}',
    campaigns TEXT[] DEFAULT '{}',
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    severity VARCHAR(20) DEFAULT 'medium',
    is_validated BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    collected_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Constraints
    CONSTRAINT intelligence_name_length CHECK (length(name) >= 2),
    CONSTRAINT intelligence_type_valid CHECK (
        type IN ('report', 'advisory', 'blog', 'feed', 'manual', 'api', 'other')
    ),
    CONSTRAINT intelligence_severity_valid CHECK (
        severity IN ('critical', 'high', 'medium', 'low', 'informational')
    ),
    CONSTRAINT intelligence_url_format CHECK (
        url IS NULL OR url ~* '^https?://.*'
    )
);

-- Create indexes
CREATE INDEX idx_intelligence_tenant_id ON intelligence(tenant_id);
CREATE INDEX idx_intelligence_name ON intelligence(name);
CREATE INDEX idx_intelligence_type ON intelligence(type);
CREATE INDEX idx_intelligence_source ON intelligence(source);
CREATE INDEX idx_intelligence_severity ON intelligence(severity);
CREATE INDEX idx_intelligence_confidence ON intelligence(confidence_score);
CREATE INDEX idx_intelligence_validated ON intelligence(is_validated);
CREATE INDEX idx_intelligence_active ON intelligence(is_active);
CREATE INDEX idx_intelligence_collected_at ON intelligence(collected_at);
CREATE INDEX idx_intelligence_created_by ON intelligence(created_by);
CREATE INDEX idx_intelligence_mitre_techniques ON intelligence USING GIN(mitre_techniques);
CREATE INDEX idx_intelligence_threat_actors ON intelligence USING GIN(threat_actors);
CREATE INDEX idx_intelligence_campaigns ON intelligence USING GIN(campaigns);
CREATE INDEX idx_intelligence_iocs ON intelligence USING GIN(iocs);

-- Full-text search index
CREATE INDEX idx_intelligence_search ON intelligence USING GIN(
    to_tsvector('english', coalesce(name, '') || ' ' ||
                          coalesce(summary, '') || ' ' ||
                          coalesce(source, ''))
);

-- Enable Row Level Security
ALTER TABLE intelligence ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Intelligence is tenant-isolated
CREATE POLICY intelligence_tenant_isolation ON intelligence
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Create updated_at trigger
CREATE TRIGGER update_intelligence_updated_at
    BEFORE UPDATE ON intelligence
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();