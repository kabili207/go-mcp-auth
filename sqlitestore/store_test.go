package sqlitestore_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	mcpauth "github.com/kabili207/go-mcp-auth"
	"github.com/kabili207/go-mcp-auth/sqlitestore"
	_ "modernc.org/sqlite"
)

func TestSettingsSecret(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "app.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}

	// Instances starting together must all end up with the same secret.
	store := sqlitestore.SettingsSecret(db, "settings", "session_secret")
	secrets := make([][]byte, 8)
	var wg sync.WaitGroup
	for i := range secrets {
		wg.Go(func() {
			s, err := mcpauth.LoadSecret(ctx, store)
			if err != nil {
				t.Error(err)
			}
			secrets[i] = s
		})
	}
	wg.Wait()
	for _, s := range secrets[1:] {
		if string(s) != string(secrets[0]) {
			t.Fatalf("instances got different secrets: %q and %q", secrets[0], s)
		}
	}

	// An app switching over keeps the secret it already had.
	existing := "an-existing-secret-of-at-least-32-bytes"
	if _, err := db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES ('mcp_jwt_secret', ?)`, existing); err != nil {
		t.Fatal(err)
	}
	got, err := mcpauth.LoadSecret(ctx, sqlitestore.SettingsSecret(db, "settings", "mcp_jwt_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != existing {
		t.Errorf("secret = %q, want the stored %q", got, existing)
	}
}
