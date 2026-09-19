// Package mcpauth is an OAuth 2.1 authorization server for MCP endpoints that
// delegates user authentication to an external OpenID Connect provider, plus the
// bearer-token middleware that goes in front of the endpoint.
package mcpauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// ErrUserDenied is returned, or wrapped, by a UserResolver to refuse a user who
// authenticated correctly: unknown to the host, not yet approved, and so on.
var ErrUserDenied = errors.New("mcpauth: user denied")

// Claims is what the identity provider said about a user. Only Subject is
// always set. Tokens issued by Server carry nothing else, so a resolver sees
// Name and Email on the identity provider callback and not on later requests.
type Claims struct {
	Subject           string
	Name              string
	Email             string
	PreferredUsername string
}

// UserResolver maps an authenticated subject to the host's own user. The value
// it returns is handed back as Identity.User. Any error refuses the request.
type UserResolver interface {
	ResolveUser(ctx context.Context, claims Claims) (any, error)
}

// UserResolverFunc adapts a function to a UserResolver.
type UserResolverFunc func(ctx context.Context, claims Claims) (any, error)

func (f UserResolverFunc) ResolveUser(ctx context.Context, claims Claims) (any, error) {
	return f(ctx, claims)
}

// Identity is the authenticated caller of a request.
type Identity struct {
	Subject  string
	ClientID string
	Scope    string
	// User is whatever the host's UserResolver returned.
	User any
}

type contextKey struct{}

// IdentityFrom returns the caller Middleware authenticated, or nil.
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}

// WithIdentity is for tests of code that sits behind Middleware.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// TokenValidator turns a bearer token into an Identity, or nil if the token is
// not one it accepts. Server and OIDCValidator both implement it, and a host
// can add its own (API keys, for instance).
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) *Identity
}

// Middleware requires a bearer token accepted by one of the validators, tried
// in order. Put Server before an OIDCValidator, so that its own tokens are
// settled locally.
//
// resourceMetadataURL goes in the WWW-Authenticate header of a 401 (RFC 9728),
// which is how an MCP client finds the authorization server. See
// Server.ResourceMetadataURL.
func Middleware(resourceMetadataURL string, validators ...TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS preflight carries no credentials
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || token == "" {
				unauthorized(w, resourceMetadataURL, "Missing or invalid Authorization header")
				return
			}

			for _, v := range validators {
				if id := v.ValidateToken(r.Context(), token); id != nil {
					next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
					return
				}
			}
			unauthorized(w, resourceMetadataURL, "Invalid or expired token")
		})
	}
}

func unauthorized(w http.ResponseWriter, resourceMetadataURL, msg string) {
	if resourceMetadataURL != "" {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+resourceMetadataURL+`"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// HashToken is the SHA-256 hex digest under which refresh tokens and client
// secrets are stored.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
