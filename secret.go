package mcpauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// SecretStore keeps the JWT signing secret across restarts. The host implements
// it over whatever it already uses for settings: a table, a file, a secrets
// manager. This module creates no storage for it.
type SecretStore interface {
	// LoadOrStoreSecret returns the secret already stored. If there is none, it
	// stores candidate and returns that. The check and the write must be one
	// atomic step, so that instances starting together all get the same value:
	// an INSERT that ignores a key conflict followed by a SELECT, for example.
	// Read-then-write is not enough. candidate is ASCII, safe for a text column.
	LoadOrStoreSecret(ctx context.Context, candidate string) (string, error)
}

// SecretStoreFunc adapts a function to a SecretStore.
type SecretStoreFunc func(ctx context.Context, candidate string) (string, error)

func (f SecretStoreFunc) LoadOrStoreSecret(ctx context.Context, candidate string) (string, error) {
	return f(ctx, candidate)
}

// LoadSecret returns the value for Config.JWTSecret, generating it the first
// time. A host that gets its secret some other way, from its config file or the
// environment, has no need for this or for SecretStore.
func LoadSecret(ctx context.Context, store SecretStore) ([]byte, error) {
	if store == nil {
		return nil, errors.New("secret store is required")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	secret, err := store.LoadOrStoreSecret(ctx, hex.EncodeToString(b))
	if err != nil {
		return nil, fmt.Errorf("load JWT secret: %w", err)
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("stored JWT secret is %d bytes, need at least 32", len(secret))
	}
	return []byte(secret), nil
}
