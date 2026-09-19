package pgstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	mcpauth "github.com/kabili207/go-mcp-auth"
	"github.com/kabili207/go-mcp-auth/pgstore"
	_ "github.com/lib/pq"
)

// Needs a scratch database:
//
//	MCPAUTH_TEST_POSTGRES='postgres://user:pass@localhost/mcpauth_test?sslmode=disable' go test ./pgstore
func TestStore(t *testing.T) {
	dsn := os.Getenv("MCPAUTH_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("MCPAUTH_TEST_POSTGRES is not set")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, pgstore.Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, pgstore.Schema); err != nil {
		t.Fatalf("schema is not idempotent: %v", err)
	}
	store := pgstore.New(db)

	now := time.Now().Truncate(time.Second)
	id := "test_" + now.Format("150405.000000")

	// A public client: no secret, no name, no scope, which are NULL columns
	client := &mcpauth.Client{
		ClientID: id, RedirectURIs: []string{"https://claude.ai/cb", "http://localhost:1/cb"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		TokenEndpointAuthMethod: "none", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RedirectURIs) != 2 || got.RedirectURIs[1] != "http://localhost:1/cb" || got.ClientSecretHash != "" {
		t.Errorf("client = %+v", got)
	}

	code := &mcpauth.AuthCode{Code: id, ClientID: id, UserID: "sub", RedirectURI: "https://claude.ai/cb",
		CodeChallenge: "c", CodeChallengeMethod: "S256", ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if err := store.CreateAuthCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAuthCodeUsed(ctx, id); err != nil {
		t.Errorf("first use: %v", err)
	}
	if err := store.MarkAuthCodeUsed(ctx, id); !errors.Is(err, mcpauth.ErrAlreadyUsed) {
		t.Errorf("second use: %v, want ErrAlreadyUsed", err)
	}

	token := &mcpauth.RefreshToken{TokenHash: id, ClientID: id, UserID: "sub", ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if err := store.CreateRefreshToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRefreshToken(ctx, id); err != nil {
		t.Errorf("first revoke: %v", err)
	}
	if err := store.RevokeRefreshToken(ctx, id); !errors.Is(err, mcpauth.ErrAlreadyUsed) {
		t.Errorf("second revoke: %v, want ErrAlreadyUsed", err)
	}
	if rt, err := store.GetRefreshToken(ctx, id); err != nil || rt.RevokedAt == nil {
		t.Errorf("revoked token = %+v, %v", rt, err)
	}

	// The same client state twice, as a client that sends none would
	for _, idpState := range []string{id + "_a", id + "_b"} {
		p := &mcpauth.PendingAuth{State: id, ClientID: id, RedirectURI: "https://claude.ai/cb", CodeChallenge: "c",
			CodeChallengeMethod: "S256", IDPState: idpState, IDPVerifier: "v", ExpiresAt: now.Add(time.Minute), CreatedAt: now}
		if err := store.CreatePendingAuth(ctx, p); err != nil {
			t.Fatalf("pending auth %s: %v", idpState, err)
		}
	}
	if _, err := store.GetPendingAuth(ctx, id+"_b"); err != nil {
		t.Errorf("latest pending auth: %v", err)
	}
	if err := store.DeletePendingAuth(ctx, id+"_b"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPendingAuth(ctx, id+"_b"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("deleted pending auth: %v, want sql.ErrNoRows", err)
	}

	a, err := store.Secret(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := store.Secret(ctx); len(a) < 32 || string(a) != string(b) {
		t.Errorf("secrets differ or are short")
	}
}
