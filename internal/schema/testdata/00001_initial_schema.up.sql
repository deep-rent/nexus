-- Migration: 00001_initial_schema
-- Description: Creates the core user and tenant tables.

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

/* The users table stores all authentication and profile data.
  Note: Passwords should be hashed before insertion!
*/
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    bio TEXT,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- Insert a default system tenant with a bio containing tricky punctuation
INSERT INTO tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000000', 'System');

INSERT INTO users (tenant_id, email, password_hash, bio)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'admin@system.local',
    'not_a_real_hash',
    'System administrator account; do not delete; managed by automated processes.'
);
