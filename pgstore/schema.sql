CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT,                -- SHA256 hash (NULL for public clients)
    client_name TEXT,
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    response_types TEXT[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    scope TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mcp_oauth_auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES mcp_oauth_clients(client_id),
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_mcp_auth_codes_expires ON mcp_oauth_auth_codes(expires_at);

CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES mcp_oauth_clients(client_id),
    user_id TEXT NOT NULL,
    scope TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mcp_refresh_tokens_user ON mcp_oauth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_mcp_refresh_tokens_expires ON mcp_oauth_refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS mcp_oauth_pending_auth (
    state TEXT PRIMARY KEY,                -- MCP client's state parameter
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    idp_state TEXT NOT NULL,               -- State used with the identity provider
    idp_verifier TEXT NOT NULL,            -- PKCE verifier for the identity provider
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mcp_pending_auth_idp_state ON mcp_oauth_pending_auth(idp_state);
CREATE INDEX IF NOT EXISTS idx_mcp_pending_auth_expires ON mcp_oauth_pending_auth(expires_at);
