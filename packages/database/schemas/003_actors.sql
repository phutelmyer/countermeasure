-- 003_actors.sql
-- Threat actor management with confidence scoring

-- Create threat actors table
CREATE TABLE IF NOT EXISTS actors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    aliases TEXT[] DEFAULT '{}',
    description TEXT,
    motivation VARCHAR(100),
    sophistication INTEGER CHECK (sophistication BETWEEN 1 AND 5),
    country_origin VARCHAR(3), -- ISO 3166-1 alpha-3
    first_seen DATE,
    last_seen DATE,
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Constraints
    CONSTRAINT actors_name_length CHECK (length(name) >= 2),
    CONSTRAINT actors_date_logic CHECK (first_seen <= last_seen OR last_seen IS NULL),
    CONSTRAINT actors_motivation_valid CHECK (
        motivation IS NULL OR motivation IN (
            'financial', 'espionage', 'sabotage', 'activism', 'warfare', 'unknown'
        )
    )
);

-- Create indexes
CREATE INDEX idx_actors_tenant_id ON actors(tenant_id);
CREATE INDEX idx_actors_name ON actors(name);
CREATE INDEX idx_actors_aliases ON actors USING GIN(aliases);
CREATE INDEX idx_actors_motivation ON actors(motivation);
CREATE INDEX idx_actors_sophistication ON actors(sophistication);
CREATE INDEX idx_actors_country ON actors(country_origin);
CREATE INDEX idx_actors_confidence ON actors(confidence_score);
CREATE INDEX idx_actors_active ON actors(is_active);
CREATE INDEX idx_actors_created_by ON actors(created_by);

-- Full-text search index
CREATE INDEX idx_actors_search ON actors USING GIN(
    to_tsvector('english', coalesce(name, '') || ' ' ||
                          coalesce(array_to_string(aliases, ' '), '') || ' ' ||
                          coalesce(description, ''))
);

-- Enable Row Level Security
ALTER TABLE actors ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Actors are tenant-isolated
CREATE POLICY actors_tenant_isolation ON actors
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Create updated_at trigger
CREATE TRIGGER update_actors_updated_at
    BEFORE UPDATE ON actors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();