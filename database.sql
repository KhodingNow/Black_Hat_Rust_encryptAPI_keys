CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOY NULL,

    name TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    version SMALLINT NOT NULL,
    secret_hash BYTEA NOT NULL,

    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    UNIQUE (name, organization_id)

);

CREATE INDEX index_api_keys_on_organization_id ON api_keys (organization_id);
CREATE INDEX index_api_keys_on_expires_at ON api_keys (expires_at) WHERE expires_at IS NOT NULL;
