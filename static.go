package mcpauth

import (
	"context"
	"crypto/subtle"
)

// StaticTokens accepts fixed bearer tokens handed out to other systems, keyed by
// the caller's name. The Identity it returns has that name as ClientID and no
// Subject or User, since the caller is a system and not a person.
//
// It is meant for service endpoints, in a Middleware of its own. Keep it off an
// MCP endpoint whose handlers expect a resolved user.
type StaticTokens map[string]string

func (t StaticTokens) ValidateToken(ctx context.Context, token string) *Identity {
	var match string
	// Compare against every entry, so the time taken says nothing about which
	// one matched.
	for name, want := range t {
		if want != "" && subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1 {
			match = name
		}
	}
	if match == "" {
		return nil
	}
	return &Identity{ClientID: match}
}
