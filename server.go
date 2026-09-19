package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	pendingAuthTTL  = 10 * time.Minute
	authCodeTTL     = 10 * time.Minute
	accessTokenTTL  = time.Hour
	refreshTokenTTL = 30 * 24 * time.Hour

	callbackPath         = "/oauth2/callback"
	serverMetadataPath   = "/.well-known/oauth-authorization-server"
	resourceMetadataPath = "/.well-known/oauth-protected-resource"
)

// DefaultRedirectHosts are the hosted MCP clients allowed to register when
// Config.AllowedRedirectHosts is empty.
var DefaultRedirectHosts = []string{"claude.ai", "claude.com"}

// Config configures a Server.
type Config struct {
	// Issuer is this server's public base URL, e.g. "https://misty.example.com".
	// Every endpoint and the identity provider callback are built from it, never
	// from the request's Host header.
	Issuer string

	// Resource is the URL of the protected MCP endpoint, for RFC 9728 metadata.
	// Defaults to Issuer.
	Resource string

	OIDC  OIDCConfig
	Store Store
	Users UserResolver

	// JWTSecret signs access tokens (HS256) and must be at least 32 bytes. It has
	// to survive restarts, or every restart invalidates every access token. The
	// stores in this module can keep one: see their Secret method.
	JWTSecret []byte

	// AllowedRedirectHosts are the hosts a client may register an https redirect
	// URI on. Loopback is always allowed, for native clients.
	AllowedRedirectHosts []string

	// Scopes are advertised in the server metadata. They are not enforced.
	Scopes []string
}

// Server is an OAuth 2.1 authorization server for MCP clients. It registers
// clients dynamically, sends the user to the identity provider to log in, and
// issues its own tokens for the MCP endpoint.
type Server struct {
	cfg        Config
	issuer     string
	resource   string
	discovery  Discovery
	httpClient *http.Client
}

// NewServer performs OIDC discovery, so it fails if the provider is unreachable.
func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer URL is required")
	}
	if cfg.OIDC.ClientID == "" {
		return nil, errors.New("OIDC client ID is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("store is required")
	}
	if cfg.Users == nil {
		return nil, errors.New("user resolver is required")
	}
	if len(cfg.JWTSecret) < 32 {
		return nil, errors.New("JWT secret must be at least 32 bytes")
	}
	if len(cfg.AllowedRedirectHosts) == 0 {
		cfg.AllowedRedirectHosts = DefaultRedirectHosts
	}

	client := &http.Client{Timeout: idpTimeout}
	discovery, err := discover(ctx, client, cfg.OIDC)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	s := &Server{
		cfg:        cfg,
		issuer:     strings.TrimSuffix(cfg.Issuer, "/"),
		discovery:  discovery,
		httpClient: client,
	}
	s.resource = cfg.Resource
	if s.resource == "" {
		s.resource = s.issuer
	}
	return s, nil
}

// ResourceMetadataURL is the first argument Middleware wants.
func (s *Server) ResourceMetadataURL() string {
	return s.issuer + resourceMetadataPath
}

// Mount registers every endpoint at the root of mux. A host on another router
// can register the Handle methods itself at the same paths. The paths are fixed:
// the identity provider must have Issuer + "/oauth2/callback" as a redirect URI.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+serverMetadataPath, s.HandleMetadata)
	mux.HandleFunc("GET "+resourceMetadataPath, s.HandleResourceMetadata)
	// RFC 9728 puts the resource's path after the well-known segment, and
	// clients differ on which form they ask for.
	if u, err := url.Parse(s.resource); err == nil && strings.Trim(u.Path, "/") != "" {
		mux.HandleFunc("GET "+resourceMetadataPath+"/"+strings.Trim(u.Path, "/"), s.HandleResourceMetadata)
	}
	mux.HandleFunc("POST /register", s.HandleRegister)
	mux.HandleFunc("GET /authorize", s.HandleAuthorize)
	mux.HandleFunc("GET "+callbackPath, s.HandleIDPCallback)
	mux.HandleFunc("POST /token", s.HandleToken)
}

// HandleMetadata serves Authorization Server Metadata (RFC 8414).
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"registration_endpoint":                 s.issuer + "/register",
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	if len(s.cfg.Scopes) > 0 {
		metadata["scopes_supported"] = s.cfg.Scopes
	}
	w.Header().Set("Cache-Control", "max-age=3600")
	writeJSON(w, http.StatusOK, metadata)
}

// HandleResourceMetadata serves Protected Resource Metadata (RFC 9728).
func (s *Server) HandleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "max-age=3600")
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"bearer_methods_supported": []string{"header"},
	})
}

// Registration is anonymous and there is no consent page, so an open redirect
// list would let anyone mint a client that receives a logged-in user's
// authorization code from a single crafted link.
func (s *Server) allowedRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	return parsed.Scheme == "https" && slices.Contains(s.cfg.AllowedRedirectHosts, host)
}

// HandleRegister handles Dynamic Client Registration (RFC 7591).
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		Scope                   string   `json:"scope"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		oauthError(w, "invalid_client_metadata", "Failed to read request body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		oauthError(w, "invalid_client_metadata", "Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		oauthError(w, "invalid_client_metadata", "redirect_uris is required", http.StatusBadRequest)
		return
	}
	for _, uri := range req.RedirectURIs {
		if !s.allowedRedirectURI(uri) {
			oauthError(w, "invalid_redirect_uri", "redirect_uris must point to an allowed MCP client host", http.StatusBadRequest)
			return
		}
	}

	switch req.TokenEndpointAuthMethod {
	case "":
		req.TokenEndpointAuthMethod = "none"
	case "none", "client_secret_post":
	default:
		oauthError(w, "invalid_client_metadata", "Unsupported token_endpoint_auth_method", http.StatusBadRequest)
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}

	clientID, err := randomHex(16)
	if err != nil {
		oauthError(w, "server_error", "Failed to generate client ID", http.StatusInternalServerError)
		return
	}
	clientID = "mcp_" + clientID

	var clientSecret, clientSecretHash string
	if req.TokenEndpointAuthMethod == "client_secret_post" {
		clientSecret, err = randomHex(32)
		if err != nil {
			oauthError(w, "server_error", "Failed to generate client secret", http.StatusInternalServerError)
			return
		}
		clientSecretHash = HashToken(clientSecret)
	}

	now := time.Now()
	client := &Client{
		ClientID:                clientID,
		ClientSecretHash:        clientSecretHash,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if err := s.cfg.Store.CreateClient(r.Context(), client); err != nil {
		slog.Error("MCP OAuth: failed to create client", "error", err)
		oauthError(w, "server_error", "Failed to register client", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                req.GrantTypes,
		"response_types":             req.ResponseTypes,
		"token_endpoint_auth_method": req.TokenEndpointAuthMethod,
		"scope":                      req.Scope,
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret
	}
	writeJSON(w, http.StatusCreated, resp)
}

// HandleAuthorize validates the request and sends the user to the identity
// provider to log in.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if clientID == "" {
		oauthError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		oauthError(w, "unsupported_response_type", "Only response_type=code is supported", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		oauthError(w, "invalid_request", "PKCE with S256 is required", http.StatusBadRequest)
		return
	}

	client, err := s.cfg.Store.GetClient(r.Context(), clientID)
	if err != nil {
		oauthError(w, "invalid_client", "Unknown client", http.StatusBadRequest)
		return
	}

	if redirectURI == "" {
		if len(client.RedirectURIs) != 1 {
			oauthError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
			return
		}
		redirectURI = client.RedirectURIs[0]
	}
	// The allowlist is checked again here so that a client registered before it
	// existed, or under a wider one, cannot be used.
	if !slices.Contains(client.RedirectURIs, redirectURI) || !s.allowedRedirectURI(redirectURI) {
		oauthError(w, "invalid_redirect_uri", "redirect_uri does not match registered URIs", http.StatusBadRequest)
		return
	}

	idpState, err := randomHex(32)
	if err != nil {
		oauthError(w, "server_error", "Failed to generate state", http.StatusInternalServerError)
		return
	}
	idpVerifier, err := randomHex(32)
	if err != nil {
		oauthError(w, "server_error", "Failed to generate verifier", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	pending := &PendingAuth{
		State:               q.Get("state"),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               q.Get("scope"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		IDPState:            idpState,
		IDPVerifier:         idpVerifier,
		ExpiresAt:           now.Add(pendingAuthTTL),
		CreatedAt:           now,
	}
	if err := s.cfg.Store.CreatePendingAuth(r.Context(), pending); err != nil {
		slog.Error("MCP OAuth: failed to store pending auth", "error", err)
		oauthError(w, "server_error", "Failed to process authorization", http.StatusInternalServerError)
		return
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", s.cfg.OIDC.ClientID)
	params.Set("redirect_uri", s.issuer+callbackPath)
	params.Set("scope", "openid profile email")
	params.Set("state", idpState)
	params.Set("code_challenge", s256Challenge(idpVerifier))
	params.Set("code_challenge_method", "S256")

	http.Redirect(w, r, s.discovery.AuthorizationEndpoint+"?"+params.Encode(), http.StatusFound)
}

// HandleIDPCallback receives the user back from the identity provider and
// hands the MCP client its authorization code.
func (s *Server) HandleIDPCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	if errorParam := q.Get("error"); errorParam != "" {
		slog.Error("MCP OAuth: identity provider returned an error", "error", errorParam, "description", q.Get("error_description"))
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}
	idpCode, idpState := q.Get("code"), q.Get("state")
	if idpCode == "" || idpState == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	pending, err := s.cfg.Store.GetPendingAuth(ctx, idpState)
	if err != nil {
		http.Error(w, "Invalid or expired authorization session", http.StatusBadRequest)
		return
	}
	// One attempt per session, whatever happens next
	_ = s.cfg.Store.DeletePendingAuth(ctx, idpState)
	if time.Now().After(pending.ExpiresAt) {
		http.Error(w, "Authorization session expired", http.StatusBadRequest)
		return
	}

	idpToken, err := s.exchangeIDPCode(ctx, idpCode, pending.IDPVerifier)
	if err != nil {
		slog.Error("MCP OAuth: identity provider token exchange failed", "error", err)
		http.Error(w, "Failed to complete authentication", http.StatusInternalServerError)
		return
	}
	claims, err := fetchUserinfo(ctx, s.httpClient, s.discovery.UserinfoEndpoint, idpToken)
	if err != nil {
		slog.Error("MCP OAuth: failed to get user info", "error", err)
		http.Error(w, "Failed to retrieve user information", http.StatusInternalServerError)
		return
	}

	if _, err := s.cfg.Users.ResolveUser(ctx, *claims); err != nil {
		if errors.Is(err, ErrUserDenied) {
			slog.Warn("MCP OAuth: user denied", "subject", claims.Subject, "error", err)
			http.Error(w, "This account is not allowed to use this service", http.StatusForbidden)
			return
		}
		slog.Error("MCP OAuth: failed to resolve user", "subject", claims.Subject, "error", err)
		http.Error(w, "Failed to look up user account", http.StatusInternalServerError)
		return
	}

	authCode, err := randomHex(32)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	code := &AuthCode{
		Code:                authCode,
		ClientID:            pending.ClientID,
		UserID:              claims.Subject,
		RedirectURI:         pending.RedirectURI,
		Scope:               pending.Scope,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		ExpiresAt:           now.Add(authCodeTTL),
		CreatedAt:           now,
	}
	if err := s.cfg.Store.CreateAuthCode(ctx, code); err != nil {
		slog.Error("MCP OAuth: failed to store auth code", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Validated against the allowlist at /authorize, so it parses
	redirectURL, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	rq := redirectURL.Query()
	rq.Set("code", authCode)
	if pending.State != "" {
		rq.Set("state", pending.State)
	}
	redirectURL.RawQuery = rq.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// HandleToken handles the authorization_code and refresh_token grants.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "Failed to parse form", http.StatusBadRequest)
		return
	}

	switch grantType := r.PostFormValue("grant_type"); grantType {
	case "authorization_code":
		s.authCodeGrant(w, r)
	case "refresh_token":
		s.refreshTokenGrant(w, r)
	default:
		oauthError(w, "unsupported_grant_type", "Unsupported grant_type", http.StatusBadRequest)
	}
}

func (s *Server) authCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	codeVerifier := r.PostFormValue("code_verifier")

	if code == "" || clientID == "" || codeVerifier == "" {
		oauthError(w, "invalid_request", "code, client_id, and code_verifier are required", http.StatusBadRequest)
		return
	}

	authCode, err := s.cfg.Store.GetAuthCode(ctx, code)
	if err != nil {
		oauthError(w, "invalid_grant", "Invalid authorization code", http.StatusBadRequest)
		return
	}
	switch {
	case authCode.Used:
		oauthError(w, "invalid_grant", "Authorization code already used", http.StatusBadRequest)
		return
	case time.Now().After(authCode.ExpiresAt):
		oauthError(w, "invalid_grant", "Authorization code expired", http.StatusBadRequest)
		return
	case authCode.ClientID != clientID:
		oauthError(w, "invalid_grant", "Client ID mismatch", http.StatusBadRequest)
		return
	case authCode.RedirectURI != r.PostFormValue("redirect_uri"):
		oauthError(w, "invalid_grant", "Redirect URI mismatch", http.StatusBadRequest)
		return
	case !constantTimeEqual(s256Challenge(codeVerifier), authCode.CodeChallenge):
		oauthError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	if !s.authenticateClient(w, r, clientID) {
		return
	}

	if err := s.cfg.Store.MarkAuthCodeUsed(ctx, code); err != nil {
		if errors.Is(err, ErrAlreadyUsed) {
			oauthError(w, "invalid_grant", "Authorization code already used", http.StatusBadRequest)
			return
		}
		slog.Error("MCP OAuth: failed to mark code used", "error", err)
		oauthError(w, "server_error", "Internal error", http.StatusInternalServerError)
		return
	}

	s.issueTokens(w, r, authCode.UserID, clientID, authCode.Scope)
}

func (s *Server) refreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refreshToken := r.PostFormValue("refresh_token")
	clientID := r.PostFormValue("client_id")

	if refreshToken == "" || clientID == "" {
		oauthError(w, "invalid_request", "refresh_token and client_id are required", http.StatusBadRequest)
		return
	}

	tokenHash := HashToken(refreshToken)
	rt, err := s.cfg.Store.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		oauthError(w, "invalid_grant", "Invalid refresh token", http.StatusBadRequest)
		return
	}
	switch {
	case rt.RevokedAt != nil:
		oauthError(w, "invalid_grant", "Refresh token has been revoked", http.StatusBadRequest)
		return
	case time.Now().After(rt.ExpiresAt):
		oauthError(w, "invalid_grant", "Refresh token expired", http.StatusBadRequest)
		return
	case rt.ClientID != clientID:
		oauthError(w, "invalid_grant", "Client ID mismatch", http.StatusBadRequest)
		return
	}

	if !s.authenticateClient(w, r, clientID) {
		return
	}

	// Rotation must not hand out new tokens while the old one stays valid
	if err := s.cfg.Store.RevokeRefreshToken(ctx, tokenHash); err != nil {
		if errors.Is(err, ErrAlreadyUsed) {
			oauthError(w, "invalid_grant", "Refresh token already used", http.StatusBadRequest)
			return
		}
		slog.Error("MCP OAuth: failed to revoke old refresh token", "error", err)
		oauthError(w, "server_error", "Internal error", http.StatusInternalServerError)
		return
	}

	s.issueTokens(w, r, rt.UserID, clientID, rt.Scope)
}

// authenticateClient writes the error response itself when it returns false.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request, clientID string) bool {
	client, err := s.cfg.Store.GetClient(r.Context(), clientID)
	if err != nil {
		oauthError(w, "invalid_client", "Unknown client", http.StatusBadRequest)
		return false
	}
	if client.TokenEndpointAuthMethod == "client_secret_post" &&
		!constantTimeEqual(HashToken(r.PostFormValue("client_secret")), client.ClientSecretHash) {
		oauthError(w, "invalid_client", "Invalid client secret", http.StatusUnauthorized)
		return false
	}
	return true
}

type accessTokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, subject, clientID, scope string) {
	now := time.Now()

	jti, err := randomHex(16)
	if err != nil {
		oauthError(w, "server_error", "Internal error", http.StatusInternalServerError)
		return
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{s.resource},
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		ClientID: clientID,
		Scope:    scope,
	}).SignedString(s.cfg.JWTSecret)
	if err != nil {
		slog.Error("MCP OAuth: failed to sign access token", "error", err)
		oauthError(w, "server_error", "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := randomHex(32)
	if err != nil {
		oauthError(w, "server_error", "Internal error", http.StatusInternalServerError)
		return
	}
	if err := s.cfg.Store.CreateRefreshToken(r.Context(), &RefreshToken{
		TokenHash: HashToken(refreshToken),
		ClientID:  clientID,
		UserID:    subject,
		Scope:     scope,
		ExpiresAt: now.Add(refreshTokenTTL),
		CreatedAt: now,
	}); err != nil {
		slog.Error("MCP OAuth: failed to store refresh token", "error", err)
		oauthError(w, "server_error", "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
	}
	if scope != "" {
		resp["scope"] = scope
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// ValidateToken implements TokenValidator for access tokens this server issued.
// The user is resolved again on every request, so a user the host stops
// accepting loses access without waiting for the token to expire.
func (s *Server) ValidateToken(ctx context.Context, tokenString string) *Identity {
	claims := &accessTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return s.cfg.JWTSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.resource),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid || claims.Subject == "" {
		return nil
	}

	user, err := s.cfg.Users.ResolveUser(ctx, Claims{Subject: claims.Subject})
	if err != nil {
		slog.Warn("MCP OAuth: access token refused by user resolver", "subject", claims.Subject, "error", err)
		return nil
	}
	return &Identity{Subject: claims.Subject, ClientID: claims.ClientID, Scope: claims.Scope, User: user}
}

// exchangeIDPCode returns the identity provider's access token.
func (s *Server) exchangeIDPCode(ctx context.Context, code, verifier string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", s.issuer+callbackPath)
	data.Set("client_id", s.cfg.OIDC.ClientID)
	if s.cfg.OIDC.ClientSecret != "" {
		data.Set("client_secret", s.cfg.OIDC.ClientSecret)
	}
	data.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %.512s", resp.StatusCode, body)
	}

	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return "", err
	}
	if tokens.AccessToken == "" {
		return "", errors.New("token endpoint returned no access token")
	}
	return tokens.AccessToken, nil
}

func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code, description string, status int) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
