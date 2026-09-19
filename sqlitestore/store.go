// Package sqlitestore is an mcpauth.Store on SQLite. It uses database/sql only,
// so the host chooses the driver.
package sqlitestore

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	mcpauth "github.com/kabili207/go-mcp-auth"
)

//go:embed schema.sql
var schema string

type Store struct {
	db *sql.DB
}

// New creates the tables if they do not exist.
func New(ctx context.Context, db *sql.DB) (*Store, error) {
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, fmt.Errorf("create mcpauth tables: %w", err)
	}
	return &Store{db: db}, nil
}

// Cleanup deletes what has expired. Nothing depends on it running; rows are
// checked for expiry when they are read.
func (s *Store) Cleanup(ctx context.Context) error {
	now := time.Now().Unix()
	for _, q := range []string{
		`DELETE FROM mcp_oauth_auth_codes WHERE expires_at < ?`,
		`DELETE FROM mcp_oauth_pending_auth WHERE expires_at < ?`,
		`DELETE FROM mcp_oauth_refresh_tokens WHERE expires_at < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateClient(ctx context.Context, c *mcpauth.Client) error {
	redirectURIs, grantTypes, responseTypes := list(c.RedirectURIs), list(c.GrantTypes), list(c.ResponseTypes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_clients (client_id, client_secret_hash, client_name, redirect_uris,
			grant_types, response_types, token_endpoint_auth_method, scope, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, c.ClientID, c.ClientSecretHash, c.ClientName, redirectURIs, grantTypes, responseTypes,
		c.TokenEndpointAuthMethod, c.Scope, c.CreatedAt.Unix(), c.UpdatedAt.Unix())
	return err
}

func (s *Store) GetClient(ctx context.Context, clientID string) (*mcpauth.Client, error) {
	var c mcpauth.Client
	var redirectURIs, grantTypes, responseTypes string
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, client_secret_hash, client_name, redirect_uris,
			grant_types, response_types, token_endpoint_auth_method, scope, created_at, updated_at
		FROM mcp_oauth_clients WHERE client_id = ?
	`, clientID).Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &redirectURIs,
		&grantTypes, &responseTypes, &c.TokenEndpointAuthMethod, &c.Scope, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		src string
		dst *[]string
	}{{redirectURIs, &c.RedirectURIs}, {grantTypes, &c.GrantTypes}, {responseTypes, &c.ResponseTypes}} {
		if err := json.Unmarshal([]byte(f.src), f.dst); err != nil {
			return nil, fmt.Errorf("client %s: %w", clientID, err)
		}
	}
	c.CreatedAt, c.UpdatedAt = time.Unix(createdAt, 0), time.Unix(updatedAt, 0)
	return &c, nil
}

func (s *Store) CreateAuthCode(ctx context.Context, c *mcpauth.AuthCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_auth_codes (code, client_id, user_id, redirect_uri, scope,
			code_challenge, code_challenge_method, expires_at, created_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, c.Code, c.ClientID, c.UserID, c.RedirectURI, c.Scope,
		c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt.Unix(), c.CreatedAt.Unix(), c.Used)
	return err
}

func (s *Store) GetAuthCode(ctx context.Context, code string) (*mcpauth.AuthCode, error) {
	var c mcpauth.AuthCode
	var expiresAt, createdAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT code, client_id, user_id, redirect_uri, scope,
			code_challenge, code_challenge_method, expires_at, created_at, used
		FROM mcp_oauth_auth_codes WHERE code = ?
	`, code).Scan(&c.Code, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope,
		&c.CodeChallenge, &c.CodeChallengeMethod, &expiresAt, &createdAt, &c.Used)
	if err != nil {
		return nil, err
	}
	c.ExpiresAt, c.CreatedAt = time.Unix(expiresAt, 0), time.Unix(createdAt, 0)
	return &c, nil
}

func (s *Store) MarkAuthCodeUsed(ctx context.Context, code string) error {
	return claim(s.db.ExecContext(ctx, `UPDATE mcp_oauth_auth_codes SET used = 1 WHERE code = ? AND used = 0`, code))
}

func (s *Store) CreateRefreshToken(ctx context.Context, t *mcpauth.RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_refresh_tokens (token_hash, client_id, user_id, scope, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, t.TokenHash, t.ClientID, t.UserID, t.Scope, t.ExpiresAt.Unix(), t.CreatedAt.Unix())
	return err
}

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (*mcpauth.RefreshToken, error) {
	var t mcpauth.RefreshToken
	var expiresAt, createdAt int64
	var revokedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT token_hash, client_id, user_id, scope, expires_at, created_at, revoked_at
		FROM mcp_oauth_refresh_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&t.TokenHash, &t.ClientID, &t.UserID, &t.Scope, &expiresAt, &createdAt, &revokedAt)
	if err != nil {
		return nil, err
	}
	t.ExpiresAt, t.CreatedAt = time.Unix(expiresAt, 0), time.Unix(createdAt, 0)
	if revokedAt.Valid {
		at := time.Unix(revokedAt.Int64, 0)
		t.RevokedAt = &at
	}
	return &t, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return claim(s.db.ExecContext(ctx,
		`UPDATE mcp_oauth_refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`,
		time.Now().Unix(), tokenHash))
}

func (s *Store) CreatePendingAuth(ctx context.Context, p *mcpauth.PendingAuth) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_oauth_pending_auth (idp_state, state, client_id, redirect_uri, scope,
			code_challenge, code_challenge_method, idp_verifier, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, p.IDPState, p.State, p.ClientID, p.RedirectURI, p.Scope,
		p.CodeChallenge, p.CodeChallengeMethod, p.IDPVerifier, p.ExpiresAt.Unix(), p.CreatedAt.Unix())
	return err
}

func (s *Store) GetPendingAuth(ctx context.Context, idpState string) (*mcpauth.PendingAuth, error) {
	var p mcpauth.PendingAuth
	var expiresAt, createdAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT idp_state, state, client_id, redirect_uri, scope,
			code_challenge, code_challenge_method, idp_verifier, expires_at, created_at
		FROM mcp_oauth_pending_auth WHERE idp_state = ?
	`, idpState).Scan(&p.IDPState, &p.State, &p.ClientID, &p.RedirectURI, &p.Scope,
		&p.CodeChallenge, &p.CodeChallengeMethod, &p.IDPVerifier, &expiresAt, &createdAt)
	if err != nil {
		return nil, err
	}
	p.ExpiresAt, p.CreatedAt = time.Unix(expiresAt, 0), time.Unix(createdAt, 0)
	return &p, nil
}

func (s *Store) DeletePendingAuth(ctx context.Context, idpState string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth_pending_auth WHERE idp_state = ?`, idpState)
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

func list(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}
