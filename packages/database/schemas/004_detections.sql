-- 004_detections.sql
-- Detection rule management with validation and MITRE mapping

-- Create detections table
CREATE TABLE IF NOT EXISTS detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium',
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    validated BOOLEAN DEFAULT FALSE,
    validation_date TIMESTAMPTZ,
    validation_notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    validated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Constraints
    CONSTRAINT detections_name_length CHECK (length(name) >= 2),
    CONSTRAINT detections_content_length CHECK (length(content) >= 10),
    CONSTRAINT detections_type_valid CHECK (
        type IN ('sigma', 'yara', 'snort', 'suricata', 'splunk', 'kql', 'custom')
    ),
    CONSTRAINT detections_severity_valid CHECK (
        severity IN ('critical', 'high', 'medium', 'low', 'informational')
    )
);

-- Create indexes
CREATE INDEX idx_detections_tenant_id ON detections(tenant_id);
CREATE INDEX idx_detections_name ON detections(name);
CREATE INDEX idx_detections_type ON detections(type);
CREATE INDEX idx_detections_severity ON detections(severity);
CREATE INDEX idx_detections_confidence ON detections(confidence);
CREATE INDEX idx_detections_validated ON detections(validated);
CREATE INDEX idx_detections_active ON detections(is_active);
CREATE INDEX idx_detections_created_by ON detections(created_by);
CREATE INDEX idx_detections_mitre_tactics ON detections USING GIN(mitre_tactics);
CREATE INDEX idx_detections_mitre_techniques ON detections USING GIN(mitre_techniques);
CREATE INDEX idx_detections_tags ON detections USING GIN(tags);

-- Full-text search index
CREATE INDEX idx_detections_search ON detections USING GIN(
    to_tsvector('english', coalesce(name, '') || ' ' ||
                          coalesce(description, '') || ' ' ||
                          coalesce(array_to_string(tags, ' '), ''))
);

-- Enable Row Level Security
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Detections are tenant-isolated
CREATE POLICY detections_tenant_isolation ON detections
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Create updated_at trigger
CREATE TRIGGER update_detections_updated_at
    BEFORE UPDATE ON detections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();