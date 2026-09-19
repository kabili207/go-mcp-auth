package mcpauth

import (
	"context"
	"errors"
	"time"
)

// ErrAlreadyUsed is what MarkAuthCodeUsed and RevokeRefreshToken return when
// another request got there first.
var ErrAlreadyUsed = errors.New("mcpauth: already used")

// Store holds the authorization server's state. UserID fields hold the identity
// provider's subject, never a host user ID, so one schema serves every host.
//
// MarkAuthCodeUsed and RevokeRefreshToken must be compare-and-set: they change
// the row only if it is still unused, and return ErrAlreadyUsed when it was not.
// An unconditional update lets two concurrent redemptions both succeed, and
// lets a refresh token survive its own rotation.
type Store interface {
	CreateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, clientID string) (*Client, error)

	CreateAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	MarkAuthCodeUsed(ctx context.Context, code string) error

	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error

	CreatePendingAuth(ctx context.Context, pending *PendingAuth) error
	GetPendingAuth(ctx context.Context, idpState string) (*PendingAuth, error)
	DeletePendingAuth(ctx context.Context, idpState string) error
}

// Client is a dynamically registered MCP client (RFC 7591).
type Client struct {
	ClientID                string
	ClientSecretHash        string // empty for public clients
	ClientName              string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	Scope                   string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// AuthCode is a single-use authorization code.
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	CreatedAt           time.Time
	Used                bool
}

// RefreshToken is stored by hash. The raw token is only ever held by the client.
type RefreshToken struct {
	TokenHash string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

// PendingAuth carries an authorization request across the round trip to the
// identity provider. It is looked up by IDPState, which this server generates.
// State is the MCP client's own value and may be empty or repeated.
type PendingAuth struct {
	State               string
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	IDPState            string
	IDPVerifier         string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}
