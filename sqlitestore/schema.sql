-- Times are unix seconds, so the schema does not depend on how a particular
-- SQLite driver maps time.Time. String lists are JSON arrays.

CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL DEFAULT '',
    client_name TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    response_types TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    scope TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_oauth_auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

-- Keyed by the state this server generates. The client's own state can be
-- empty or repeated, so it cannot be the key.
CREATE TABLE IF NOT EXISTS mcp_oauth_pending_auth (
    idp_state TEXT PRIMARY KEY,
    state TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    idp_verifier TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_oauth_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
