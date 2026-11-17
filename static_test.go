package mcpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mcpauth "github.com/kabili207/go-mcp-auth"
)

func TestStaticTokens(t *testing.T) {
	tokens := mcpauth.StaticTokens{"millie": "millie-token", "misty": "misty-token", "unset": ""}
	var got *mcpauth.Identity
	protected := mcpauth.Middleware("", tokens)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = mcpauth.IdentityFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/lookup", nil)
	req.Header.Set("Authorization", "Bearer misty-token")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got == nil || got.ClientID != "misty" || got.Subject != "" || got.User != nil {
		t.Errorf("identity = %+v, want only ClientID misty", got)
	}

	for name, header := range map[string]string{
		"no header":   "",
		"wrong token": "Bearer nope",
		"empty token": "Bearer ",
		"prefix":      "Bearer misty",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/lookup", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("%s: WWW-Authenticate = %q, want Bearer", name, got)
		}
	}
}

// An entry with no token must not let anything in, even a caller that gets an
// empty token past the middleware.
func TestStaticTokensIgnoreEmptyEntries(t *testing.T) {
	tokens := mcpauth.StaticTokens{"unset": ""}
	if id := tokens.ValidateToken(context.Background(), ""); id != nil {
		t.Errorf("empty token accepted as %+v", id)
	}
}
