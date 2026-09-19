// Package pgstore is an mcpauth.Store on PostgreSQL.
package pgstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"

	mcpauth "github.com/kabili207/go-mcp-auth"
	"github.com/lib/pq"
)

// Schema creates the tables, for the host to run from its own migrations. It is
// idempotent. The settings table behind Secret is not in it; Secret creates that.
//
//go:embed schema.sql
var Schema string

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Secret returns the JWT signing secret kept in the database, generating it on
// first use. Concurrent first calls all end up with the same value.
func (s *Store) Secret(ctx context.Context) ([]byte, error) {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS mcp_oauth_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO mcp_oauth_settings (key, value) VALUES ('jwt_secret', $1) ON CONFLICT (key) DO NOTHING`,
		hex.EncodeToString(b)); err != nil {
		return nil, err
	}
	var secret string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM mcp_oauth_settings WHERE key = 'jwt_secret'`).Scan(&secret); err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

// Cleanup deletes what has expired. Nothing depends on it running; rows are
// checked for expiry when they are read.
func (s *Store) Cleanup(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM mcp_oauth_auth_codes WHERE expires_at < NOW()`,
		`DELETE FROM mcp_oauth_pending_auth WHERE expires_at < NOW()`,
		`DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < NOW()`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateClient(ctx context.Context, c *mcpauth.Client) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
			grant_types, response_types, token_endpoint_auth_method, scope, created_at, updated_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8, $9, $10)
	`, c.ClientID, c.ClientSecretHash, c.ClientName,
		pq.Array(c.RedirectURIs), pq.Array(c.GrantTypes), pq.Array(c.ResponseTypes),
		c.TokenEndpointAuthMethod, c.Scope, c.CreatedAt, c.UpdatedAt)
	return err
}

func (s *Store) GetClient(ctx context.Context, clientID string) (*mcpauth.Client, error) {
	var c mcpauth.Client
	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, COALESCE(client_secret_hash, ''), COALESCE(client_name, ''), redirect_uris,
			grant_types, response_types, token_endpoint_auth_method, COALESCE(scope, ''), created_at, updated_at
		FROM mcp_oauth_clients WHERE client_id = $1
	`, clientID).Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName,
		pq.Array(&c.RedirectURIs), pq.Array(&c.GrantTypes), pq.Array(&c.ResponseTypes),
		&c.TokenEndpointAuthMethod, &c.Scope, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) CreateAuthCode(ctx context.Context, c *mcpauth.AuthCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_auth_codes (code, client_id, user_id, redirect_uri, scope,
			code_challenge, code_challenge_method, expires_at, created_at, used)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, c.Code, c.ClientID, c.UserID, c.RedirectURI, c.Scope,
		c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt, c.CreatedAt, c.Used)
	return err
}

func (s *Store) GetAuthCode(ctx context.Context, code string) (*mcpauth.AuthCode, error) {
	var c mcpauth.AuthCode
	err := s.db.QueryRowContext(ctx, `
		SELECT code, client_id, user_id, redirect_uri, COALESCE(scope, ''),
			code_challenge, code_challenge_method, expires_at, created_at, used
		FROM mcp_oauth_auth_codes WHERE code = $1
	`, code).Scan(&c.Code, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope,
		&c.CodeChallenge, &c.CodeChallengeMethod, &c.ExpiresAt, &c.CreatedAt, &c.Used)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) MarkAuthCodeUsed(ctx context.Context, code string) error {
	return claim(s.db.ExecContext(ctx, `UPDATE mcp_oauth_auth_codes SET used = TRUE WHERE code = $1 AND used = FALSE`, code))
}

func (s *Store) CreateRefreshToken(ctx context.Context, t *mcpauth.RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_refresh_tokens (token_hash, client_id, user_id, scope, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, t.TokenHash, t.ClientID, t.UserID, t.Scope, t.ExpiresAt, t.CreatedAt)
	return err
}

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (*mcpauth.RefreshToken, error) {
	var t mcpauth.RefreshToken
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT token_hash, client_id, user_id, COALESCE(scope, ''), expires_at, created_at, revoked_at
		FROM mcp_oauth_refresh_tokens WHERE token_hash = $1
	`, tokenHash).Scan(&t.TokenHash, &t.ClientID, &t.UserID, &t.Scope, &t.ExpiresAt, &t.CreatedAt, &revokedAt)
	if err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	return &t, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return claim(s.db.ExecContext(ctx,
		`UPDATE mcp_oauth_refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash))
}

// CreatePendingAuth replaces a row with the same state. The table's key is the
// MCP client's state, which the client chooses and may leave empty, so a second
// flow with the same value would otherwise fail on the key.
func (s *Store) CreatePendingAuth(ctx context.Context, p *mcpauth.PendingAuth) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_pending_auth (state, client_id, redirect_uri, scope,
			code_challenge, code_challenge_method, idp_state, idp_verifier, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (state) DO UPDATE SET
			client_id = EXCLUDED.client_id, redirect_uri = EXCLUDED.redirect_uri, scope = EXCLUDED.scope,
			code_challenge = EXCLUDED.code_challenge, code_challenge_method = EXCLUDED.code_challenge_method,
			idp_state = EXCLUDED.idp_state, idp_verifier = EXCLUDED.idp_verifier,
			expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at
	`, p.State, p.ClientID, p.RedirectURI, p.Scope, p.CodeChallenge, p.CodeChallengeMethod,
		p.IDPState, p.IDPVerifier, p.ExpiresAt, p.CreatedAt)
	return err
}

func (s *Store) GetPendingAuth(ctx context.Context, idpState string) (*mcpauth.PendingAuth, error) {
	var p mcpauth.PendingAuth
	err := s.db.QueryRowContext(ctx, `
		SELECT state, client_id, redirect_uri, COALESCE(scope, ''),
			code_challenge, code_challenge_method, idp_state, idp_verifier, expires_at, created_at
		FROM mcp_oauth_pending_auth WHERE idp_state = $1
	`, idpState).Scan(&p.State, &p.ClientID, &p.RedirectURI, &p.Scope,
		&p.CodeChallenge, &p.CodeChallengeMethod, &p.IDPState, &p.IDPVerifier, &p.ExpiresAt, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) DeletePendingAuth(ctx context.Context, idpState string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth_pending_auth WHERE idp_state = $1`, idpState)
	return err
}

// claim turns a compare-and-set update that matched nothing into ErrAlreadyUsed.
func claim(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return mcpauth.ErrAlreadyUsed
	}
	return nil
}
