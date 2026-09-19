package mcpauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig identifies the external identity provider.
type OIDCConfig struct {
	// IssuerURL is the provider's base URL.
	IssuerURL string

	// ClientID is this application's client at the provider. Server needs it.
	// OIDCValidator, when it is set, requires it in a token's audience.
	ClientID string

	// ClientSecret is for confidential clients. PKCE is used either way.
	ClientSecret string

	// DiscoveryURL overrides IssuerURL + "/.well-known/openid-configuration".
	// Kanidm serves discovery per client:
	//   https://idm.example.com/oauth2/openid/CLIENT_ID/.well-known/openid-configuration
	DiscoveryURL string
}

// Discovery is the part of the provider's discovery document used here.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

const (
	idpTimeout = 10 * time.Second
	jwksTTL    = time.Hour
	// jwksMissInterval limits refetches caused by an unknown key ID. Anyone can send
	// a token with a made-up kid, and each one would otherwise cost a request to the
	// provider.
	jwksMissInterval = time.Minute
)

// Only asymmetric algorithms: the key comes from the provider's JWKS.
var oidcSigningMethods = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

func discover(ctx context.Context, client *http.Client, cfg OIDCConfig) (Discovery, error) {
	var d Discovery
	if cfg.IssuerURL == "" {
		return d, errors.New("OIDC issuer URL is required")
	}
	discoveryURL := cfg.DiscoveryURL
	if discoveryURL == "" {
		discoveryURL = strings.TrimSuffix(cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return d, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return d, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return d, fmt.Errorf("discovery returned %d: %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return d, fmt.Errorf("parse discovery document: %w", err)
	}
	return d, nil
}

// OIDCValidator accepts tokens issued directly by the identity provider: JWTs
// checked against its JWKS, and opaque tokens checked at its userinfo endpoint.
//
// The userinfo endpoint says who a token belongs to, not which client it was
// issued for, and most providers answer for any client's token. So it is only
// asked about tokens that are not JWTs. A JWT that fails validation is refused:
// falling back would let a token minted for another application skip the
// audience check.
type OIDCValidator struct {
	config     OIDCConfig
	users      UserResolver
	httpClient *http.Client
	discovery  Discovery

	jwksMu       sync.RWMutex
	jwks         []jsonWebKey
	jwksTime     time.Time
	jwksMissTime time.Time // last refetch caused by an unknown key ID
}

// NewOIDCValidator performs discovery, so it fails if the provider is unreachable.
func NewOIDCValidator(ctx context.Context, config OIDCConfig, users UserResolver) (*OIDCValidator, error) {
	if users == nil {
		return nil, errors.New("user resolver is required")
	}
	client := &http.Client{Timeout: idpTimeout}
	discovery, err := discover(ctx, client, config)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	return &OIDCValidator{config: config, users: users, httpClient: client, discovery: discovery}, nil
}

func (v *OIDCValidator) Discovery() Discovery { return v.discovery }

// ValidateToken implements TokenValidator.
func (v *OIDCValidator) ValidateToken(ctx context.Context, token string) *Identity {
	if strings.Count(token, ".") == 2 {
		return v.validateJWT(ctx, token)
	}
	return v.validateViaUserinfo(ctx, token)
}

type oidcClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
	Azp               string `json:"azp,omitempty"`
}

func (v *OIDCValidator) validateJWT(ctx context.Context, tokenString string) *Identity {
	claims := &oidcClaims{}
	opts := []jwt.ParserOption{
		jwt.WithIssuer(v.discovery.Issuer),
		jwt.WithValidMethods(oidcSigningMethods),
		jwt.WithExpirationRequired(),
	}
	if v.config.ClientID != "" {
		opts = append(opts, jwt.WithAudience(v.config.ClientID))
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no key ID")
		}
		return v.signingKey(ctx, kid)
	}, opts...)
	if err != nil || !token.Valid || claims.Subject == "" {
		slog.Debug("OIDC token rejected", "error", err)
		return nil
	}

	clientID := claims.ClientID
	if clientID == "" {
		clientID = claims.Azp
	}
	return v.identity(ctx, clientID, Claims{
		Subject:           claims.Subject,
		Name:              claims.Name,
		Email:             claims.Email,
		PreferredUsername: claims.PreferredUsername,
	})
}

func (v *OIDCValidator) validateViaUserinfo(ctx context.Context, token string) *Identity {
	claims, err := fetchUserinfo(ctx, v.httpClient, v.discovery.UserinfoEndpoint, token)
	if err != nil {
		return nil
	}
	return v.identity(ctx, "", *claims)
}

func (v *OIDCValidator) identity(ctx context.Context, clientID string, claims Claims) *Identity {
	user, err := v.users.ResolveUser(ctx, claims)
	if err != nil {
		slog.Warn("OIDC token refused by user resolver", "subject", claims.Subject, "error", err)
		return nil
	}
	return &Identity{Subject: claims.Subject, ClientID: clientID, User: user}
}

func fetchUserinfo(ctx context.Context, client *http.Client, endpoint, accessToken string) (*Claims, error) {
	if endpoint == "" {
		return nil, errors.New("identity provider has no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, body)
	}

	var info struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	if info.Sub == "" {
		return nil, errors.New("userinfo has no subject")
	}
	return &Claims{Subject: info.Sub, Name: info.Name, Email: info.Email, PreferredUsername: info.PreferredUsername}, nil
}

func (v *OIDCValidator) signingKey(ctx context.Context, kid string) (any, error) {
	v.jwksMu.RLock()
	fresh := v.jwks != nil && time.Since(v.jwksTime) < jwksTTL
	key := findKey(v.jwks, kid)
	missAllowed := time.Since(v.jwksMissTime) >= jwksMissInterval
	v.jwksMu.RUnlock()

	if fresh && key != nil {
		return key.publicKey()
	}
	// A fresh cache without the key may mean the provider rotated since the last
	// fetch, so look again, but not for every unknown kid a caller sends.
	if fresh && !missAllowed {
		return nil, fmt.Errorf("key not found: %s", kid)
	}

	if err := v.refreshJWKS(ctx, fresh); err != nil {
		return nil, fmt.Errorf("refresh JWKS: %w", err)
	}

	v.jwksMu.RLock()
	key = findKey(v.jwks, kid)
	v.jwksMu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("key not found: %s", kid)
	}
	return key.publicKey()
}

func findKey(keys []jsonWebKey, kid string) *jsonWebKey {
	i := slices.IndexFunc(keys, func(k jsonWebKey) bool { return k.Kid == kid })
	if i < 0 {
		return nil
	}
	return &keys[i]
}

// refreshJWKS refetches the key set. afterMiss records that an unknown key ID
// caused it, which starts the jwksMissInterval wait.
func (v *OIDCValidator) refreshJWKS(ctx context.Context, afterMiss bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.discovery.JwksURI, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("JWKS returned %d: %s", resp.StatusCode, body)
	}

	var set struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}

	v.jwksMu.Lock()
	v.jwks = set.Keys
	v.jwksTime = time.Now()
	if afterMiss {
		v.jwksMissTime = v.jwksTime
	}
	v.jwksMu.Unlock()
	return nil
}

type jsonWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5c []string `json:"x5c"`
}

func (k *jsonWebKey) publicKey() (any, error) {
	if len(k.X5c) > 0 {
		if der, err := base64.StdEncoding.DecodeString(k.X5c[0]); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				return cert.PublicKey, nil
			}
		}
	}

	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode n: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode e: %w", err)
		}
		if len(n) == 0 || len(e) == 0 {
			return nil, errors.New("RSA key is missing n or e")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	}
	return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
}
