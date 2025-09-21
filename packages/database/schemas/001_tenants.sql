-- 001_tenants.sql
-- Multi-tenancy foundation with Row Level Security

-- Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    settings JSONB DEFAULT '{}',
    max_users INTEGER DEFAULT 100,
    max_storage_gb INTEGER DEFAULT 10,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Constraints
    CONSTRAINT tenants_slug_format CHECK (slug ~ '^[a-z0-9-]+$'),
    CONSTRAINT tenants_name_length CHECK (length(name) >= 2),
    CONSTRAINT tenants_max_users_positive CHECK (max_users > 0),
    CONSTRAINT tenants_max_storage_positive CHECK (max_storage_gb > 0)
);

-- Create indexes
CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_active ON tenants(is_active);
CREATE INDEX idx_tenants_created_at ON tenants(created_at);

-- Enable Row Level Security
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

-- Create updated_at trigger
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default tenant for development
INSERT INTO tenants (name, slug, description, settings)
VALUES (
    'Default Tenant',
    'default',
    'Default tenant for development and testing',
    '{"theme": "dark", "timezone": "UTC", "max_file_size_mb": 50}'
) ON CONFLICT (slug) DO NOTHING;