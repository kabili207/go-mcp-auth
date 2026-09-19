package mcpauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcpauth "github.com/kabili207/go-mcp-auth"
)

// keyServer is an identity provider that only serves discovery and a JWKS.
type keyServer struct {
	*httptest.Server
	mu      sync.Mutex
	keys    []map[string]string
	fetches int
}

func newKeyServer(t *testing.T) *keyServer {
	ks := &keyServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": ks.URL, "jwks_uri": ks.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		ks.mu.Lock()
		defer ks.mu.Unlock()
		ks.fetches++
		json.NewEncoder(w).Encode(map[string]any{"keys": ks.keys})
	})
	ks.Server = httptest.NewServer(mux)
	t.Cleanup(ks.Close)
	return ks
}

func b64(b *big.Int) string { return base64.RawURLEncoding.EncodeToString(b.Bytes()) }

func (ks *keyServer) addRSA(t *testing.T, kid string) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys = append(ks.keys, map[string]string{"kid": kid, "kty": "RSA", "n": b64(key.N), "e": b64(big.NewInt(int64(key.E)))})
	return key
}

func (ks *keyServer) addEC(t *testing.T, kid string) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys = append(ks.keys, map[string]string{"kid": kid, "kty": "EC", "crv": "P-256", "x": b64(key.X), "y": b64(key.Y)})
	return key
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOIDCValidator(t *testing.T) {
	ks := newKeyServer(t)
	rsaKey := ks.addRSA(t, "rsa-1")
	ecKey := ks.addEC(t, "ec-1")

	resolver := &users{allowed: map[string]int{"sub-amy": 7}}
	v, err := mcpauth.NewOIDCValidator(context.Background(), mcpauth.OIDCConfig{IssuerURL: ks.URL, ClientID: "my-client"}, resolver)
	if err != nil {
		t.Fatal(err)
	}

	good := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": ks.URL, "aud": "my-client", "sub": "sub-amy", "exp": time.Now().Add(time.Hour).Unix()}
	}
	with := func(k string, val any) jwt.MapClaims { c := good(); c[k] = val; return c }
	without := func(k string) jwt.MapClaims { c := good(); delete(c, k); return c }

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	for name, tc := range map[string]struct {
		token string
		valid bool
	}{
		"RS256":          {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", good()), true},
		"ES256":          {sign(t, jwt.SigningMethodES256, ecKey, "ec-1", good()), true},
		"wrong audience": {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", with("aud", "another-client")), false},
		"no audience":    {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", without("aud")), false},
		"wrong issuer":   {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", with("iss", "https://evil.example")), false},
		"expired":        {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", with("exp", time.Now().Add(-time.Hour).Unix())), false},
		"no expiry":      {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", without("exp")), false},
		"unknown user":   {sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-1", with("sub", "sub-stranger")), false},
		"forged key":     {sign(t, jwt.SigningMethodRS256, otherKey, "rsa-1", good()), false},
		"unknown kid":    {sign(t, jwt.SigningMethodRS256, otherKey, "nope", good()), false},
		// The classic confusion attack: HMAC keyed with the RSA public modulus
		"HS256 with public key": {sign(t, jwt.SigningMethodHS256, rsaKey.N.Bytes(), "rsa-1", good()), false},
	} {
		id := v.ValidateToken(context.Background(), tc.token)
		if (id != nil) != tc.valid {
			t.Errorf("%s: identity %v, want valid=%v", name, id, tc.valid)
		}
		if id != nil && (id.Subject != "sub-amy" || id.User != 7) {
			t.Errorf("%s: identity = %+v", name, id)
		}
	}
}

// A key the provider added after the last fetch is found without waiting for
// the cache to expire.
func TestOIDCValidatorKeyRotation(t *testing.T) {
	ks := newKeyServer(t)
	first := ks.addRSA(t, "rsa-1")

	resolver := &users{allowed: map[string]int{"sub-amy": 7}}
	v, err := mcpauth.NewOIDCValidator(context.Background(), mcpauth.OIDCConfig{IssuerURL: ks.URL}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": ks.URL, "sub": "sub-amy", "exp": time.Now().Add(time.Hour).Unix()}

	if v.ValidateToken(context.Background(), sign(t, jwt.SigningMethodRS256, first, "rsa-1", claims)) == nil {
		t.Fatal("token signed with the first key was rejected")
	}
	second := ks.addEC(t, "ec-2")
	if v.ValidateToken(context.Background(), sign(t, jwt.SigningMethodES256, second, "ec-2", claims)) == nil {
		t.Error("token signed with a key added after the first fetch was rejected")
	}

	// A cached key must not cost a fetch
	before := ks.fetches
	v.ValidateToken(context.Background(), sign(t, jwt.SigningMethodRS256, first, "rsa-1", claims))
	if ks.fetches != before {
		t.Errorf("JWKS fetched %d more times for a cached key", ks.fetches-before)
	}
}
