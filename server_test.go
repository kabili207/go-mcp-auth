package mcpauth_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcpauth "github.com/kabili207/go-mcp-auth"
	"github.com/kabili207/go-mcp-auth/sqlitestore"
	_ "modernc.org/sqlite"
)

const (
	issuer      = "https://mcp.example"
	redirectURI = "https://claude.ai/api/mcp/auth_callback"
	verifier    = "a-pkce-verifier-that-is-long-enough-to-be-plausible"
)

// fakeIDP is an identity provider where every login is the user in subject.
type fakeIDP struct {
	*httptest.Server
	subject string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	idp := &fakeIDP{subject: "sub-amy"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idp.URL,
			"authorization_endpoint": idp.URL + "/authorize",
			"token_endpoint":         idp.URL + "/token",
			"userinfo_endpoint":      idp.URL + "/userinfo",
			"jwks_uri":               idp.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("code") != "idp-code" || r.PostFormValue("code_verifier") == "" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "idp-access-token"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer idp-access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"sub": idp.subject, "name": "Amy", "email": "amy@example.com"})
	})
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

// users is a resolver whose allowed set can change mid-test.
type users struct {
	mu      sync.Mutex
	allowed map[string]int
}

func (u *users) ResolveUser(ctx context.Context, c mcpauth.Claims) (any, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	id, ok := u.allowed[c.Subject]
	if !ok {
		return nil, fmt.Errorf("%w: %s", mcpauth.ErrUserDenied, c.Subject)
	}
	return id, nil
}

func (u *users) deny(subject string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.allowed, subject)
}

// barrierStore holds every reader of a code or refresh token until n of them
// have read it, so they all go on to claim a row they all saw as unused. Without
// it the requests rarely overlap, and the ordinary "already used" check passes
// the test even when the store's compare-and-set is broken.
type barrierStore struct {
	mcpauth.Store
	mu      sync.Mutex
	n       int
	arrived int
	release chan struct{}
}

func (b *barrierStore) arm(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n, b.arrived, b.release = n, 0, make(chan struct{})
}

func (b *barrierStore) wait() {
	b.mu.Lock()
	if b.n == 0 {
		b.mu.Unlock()
		return
	}
	b.arrived++
	if b.arrived == b.n {
		close(b.release)
	}
	release := b.release
	b.mu.Unlock()

	select {
	case <-release:
	case <-time.After(5 * time.Second):
	}
}

func (b *barrierStore) GetAuthCode(ctx context.Context, code string) (*mcpauth.AuthCode, error) {
	c, err := b.Store.GetAuthCode(ctx, code)
	b.wait()
	return c, err
}

func (b *barrierStore) GetRefreshToken(ctx context.Context, hash string) (*mcpauth.RefreshToken, error) {
	t, err := b.Store.GetRefreshToken(ctx, hash)
	b.wait()
	return t, err
}

type fixture struct {
	t       *testing.T
	idp     *fakeIDP
	store   *sqlitestore.Store
	barrier *barrierStore
	users   *users
	server  *mcpauth.Server
	mux     *http.ServeMux
}

func newFixture(t *testing.T) *fixture {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "auth.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := sqlitestore.New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := mcpauth.LoadSecret(ctx, &memSecrets{})
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{
		t: t, idp: newFakeIDP(t), store: store, barrier: &barrierStore{Store: store},
		users: &users{allowed: map[string]int{"sub-amy": 7}},
	}
	f.server, err = mcpauth.NewServer(ctx, mcpauth.Config{
		Issuer:    issuer,
		OIDC:      mcpauth.OIDCConfig{IssuerURL: f.idp.URL, ClientID: "mcp-server"},
		Store:     f.barrier,
		Users:     f.users,
		JWTSecret: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mux = http.NewServeMux()
	f.server.Mount(f.mux)
	return f
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) postForm(path string, form url.Values) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(req)
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func (f *fixture) register(redirectURIs ...string) (int, map[string]any) {
	payload, _ := json.Marshal(map[string]any{"client_name": "test", "redirect_uris": redirectURIs})
	rec := f.do(httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(payload))))
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func challenge(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (f *fixture) authorize(clientID string) *httptest.ResponseRecorder {
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {"client-state"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	return f.do(httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
}

// login runs registration, /authorize and the identity provider callback, and
// returns the client ID with the callback's response.
func (f *fixture) login() (string, *httptest.ResponseRecorder) {
	f.t.Helper()
	status, reg := f.register(redirectURI)
	if status != http.StatusCreated {
		f.t.Fatalf("register: status %d, body %v", status, reg)
	}
	clientID := reg["client_id"].(string)

	rec := f.authorize(clientID)
	if rec.Code != http.StatusFound {
		f.t.Fatalf("authorize: status %d, body %s", rec.Code, rec.Body)
	}
	toIDP, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(toIDP.String(), f.idp.URL+"/authorize?") {
		f.t.Fatalf("authorize sent the user to %s", toIDP)
	}
	if got := toIDP.Query().Get("redirect_uri"); got != issuer+"/oauth2/callback" {
		f.t.Fatalf("identity provider redirect_uri = %q", got)
	}

	cb := url.Values{"code": {"idp-code"}, "state": {toIDP.Query().Get("state")}}
	return clientID, f.do(httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+cb.Encode(), nil))
}

// tokens logs in and redeems the code.
func (f *fixture) tokens() (clientID string, body map[string]any) {
	f.t.Helper()
	clientID, rec := f.login()
	if rec.Code != http.StatusFound {
		f.t.Fatalf("callback: status %d, body %s", rec.Code, rec.Body)
	}
	back, _ := url.Parse(rec.Header().Get("Location"))
	if back.Host != "claude.ai" || back.Query().Get("state") != "client-state" {
		f.t.Fatalf("callback sent the user to %s", back)
	}
	status, body := f.postForm("/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		f.t.Fatalf("token: status %d, body %v", status, body)
	}
	return clientID, body
}

func TestAuthorizationCodeFlow(t *testing.T) {
	f := newFixture(t)
	_, body := f.tokens()

	var got *mcpauth.Identity
	protected := mcpauth.Middleware(f.server.ResourceMetadataURL(), f.server)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = mcpauth.IdentityFrom(r.Context()) }))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+body["access_token"].(string))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || got == nil {
		t.Fatalf("status %d, identity %v", rec.Code, got)
	}
	if got.Subject != "sub-amy" || got.User != 7 {
		t.Errorf("identity = %+v, want subject sub-amy resolved to user 7", got)
	}
}

func TestMiddlewareRejects(t *testing.T) {
	f := newFixture(t)
	_, body := f.tokens()
	access := body["access_token"].(string)

	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer, "aud": issuer, "sub": "sub-amy", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("some-other-secret-of-at-least-32-bytes!"))
	unsigned, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": issuer, "aud": issuer, "sub": "sub-amy", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)

	protected := mcpauth.Middleware(f.server.ResourceMetadataURL(), f.server)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for name, header := range map[string]string{
		"no header":       "",
		"not bearer":      "Basic " + access,
		"garbage":         "Bearer nonsense",
		"wrong secret":    "Bearer " + forged,
		"alg none":        "Bearer " + unsigned,
		"refresh as auth": "Bearer " + body["refresh_token"].(string),
	} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		want := `Bearer resource_metadata="` + issuer + `/.well-known/oauth-protected-resource"`
		if got := rec.Header().Get("WWW-Authenticate"); got != want {
			t.Errorf("%s: WWW-Authenticate = %q", name, got)
		}
	}
}

func TestMiddlewareFuncBuildsURLPerRequest(t *testing.T) {
	protected := mcpauth.MiddlewareFunc(func(r *http.Request) string {
		return "https://" + r.Host + "/.well-known/oauth-protected-resource"
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for _, host := range []string{"one.example.com", "two.example.com"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", host, rec.Code)
		}
		want := `Bearer resource_metadata="https://` + host + `/.well-known/oauth-protected-resource"`
		if got := rec.Header().Get("WWW-Authenticate"); got != want {
			t.Errorf("%s: WWW-Authenticate = %q", host, got)
		}
	}
}

// A user the host stops accepting loses access before their token expires.
func TestDeniedUser(t *testing.T) {
	f := newFixture(t)
	_, body := f.tokens()
	access := body["access_token"].(string)

	if f.server.ValidateToken(context.Background(), access) == nil {
		t.Fatal("token should be valid while the user is allowed")
	}
	f.users.deny("sub-amy")
	if f.server.ValidateToken(context.Background(), access) != nil {
		t.Error("token still valid after the user was denied")
	}

	if _, rec := f.login(); rec.Code != http.StatusForbidden {
		t.Errorf("callback for a denied user: status %d, want 403", rec.Code)
	}
}

func TestRegisterRedirectAllowlist(t *testing.T) {
	f := newFixture(t)
	for uri, want := range map[string]int{
		"https://claude.ai/api/mcp/auth_callback": http.StatusCreated,
		"https://claude.com/cb":                   http.StatusCreated,
		"http://localhost:33418/callback":         http.StatusCreated,
		"http://127.0.0.1:8080/cb":                http.StatusCreated,
		"http://[::1]:8080/cb":                    http.StatusCreated,
		"http://claude.ai/cb":                     http.StatusBadRequest,
		"https://claude.ai.evil.example/cb":       http.StatusBadRequest,
		"https://evil.example/claude.ai":          http.StatusBadRequest,
		"https://claude.ai@evil.example/cb":       http.StatusBadRequest,
		"https://evil.example/cb":                 http.StatusBadRequest,
		"javascript:alert(1)":                     http.StatusBadRequest,
		"claude.ai":                               http.StatusBadRequest,
	} {
		if status, body := f.register(uri); status != want {
			t.Errorf("%s: status %d, want %d (%v)", uri, status, want, body)
		}
	}
	if status, _ := f.register(redirectURI, "https://evil.example/cb"); status != http.StatusBadRequest {
		t.Errorf("one bad URI among good ones: status %d, want 400", status)
	}
}

// A client that got into the store some other way, or before the allowlist
// existed, still cannot send a code to a host that is not allowed.
func TestAuthorizeRechecksAllowlist(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	if err := f.store.CreateClient(context.Background(), &mcpauth.Client{
		ClientID: "mcp_old", RedirectURIs: []string{"https://evil.example/cb"},
		TokenEndpointAuthMethod: "none", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {"mcp_old"}, "redirect_uri": {"https://evil.example/cb"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	rec := f.do(httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400; Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	f := newFixture(t)
	_, reg := f.register(redirectURI)
	for name, q := range map[string]url.Values{
		"no challenge": {"response_type": {"code"}, "client_id": {reg["client_id"].(string)}, "redirect_uri": {redirectURI}},
		"plain":        {"response_type": {"code"}, "client_id": {reg["client_id"].(string)}, "redirect_uri": {redirectURI}, "code_challenge": {verifier}, "code_challenge_method": {"plain"}},
	} {
		if rec := f.do(httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
}

func TestTokenRejects(t *testing.T) {
	for name, change := range map[string]func(url.Values){
		"wrong verifier":     func(v url.Values) { v.Set("code_verifier", "not-the-verifier") },
		"wrong client":       func(v url.Values) { v.Set("client_id", "mcp_someone_else") },
		"wrong redirect_uri": func(v url.Values) { v.Set("redirect_uri", "https://claude.ai/other") },
		"unknown code":       func(v url.Values) { v.Set("code", "nope") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			clientID, rec := f.login()
			back, _ := url.Parse(rec.Header().Get("Location"))
			form := url.Values{
				"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
				"client_id": {clientID}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
			}
			change(form)
			if status, body := f.postForm("/token", form); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Errorf("status %d, body %v", status, body)
			}
		})
	}
}

func TestAuthCodeIsSingleUse(t *testing.T) {
	f := newFixture(t)
	clientID, rec := f.login()
	back, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
	if got := f.race("/token", form); got != 1 {
		t.Errorf("%d of the concurrent redemptions succeeded, want exactly 1", got)
	}
	if status, _ := f.postForm("/token", form); status != http.StatusBadRequest {
		t.Errorf("replay: status %d, want 400", status)
	}
}

func TestRefreshRotation(t *testing.T) {
	f := newFixture(t)
	clientID, body := f.tokens()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {clientID}}

	if got := f.race("/token", form); got != 1 {
		t.Errorf("%d of the concurrent refreshes succeeded, want exactly 1", got)
	}
	if status, _ := f.postForm("/token", form); status != http.StatusBadRequest {
		t.Errorf("reuse of a rotated refresh token: status %d, want 400", status)
	}
}

func TestRefreshIssuesWorkingTokens(t *testing.T) {
	f := newFixture(t)
	clientID, body := f.tokens()
	status, next := f.postForm("/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}, "client_id": {clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh: status %d, body %v", status, next)
	}
	if next["refresh_token"] == body["refresh_token"] {
		t.Error("refresh token was not rotated")
	}
	if f.server.ValidateToken(context.Background(), next["access_token"].(string)) == nil {
		t.Error("access token from a refresh is not valid")
	}
	if status, _ := f.postForm("/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {next["refresh_token"].(string)}, "client_id": {"mcp_someone_else"},
	}); status != http.StatusBadRequest {
		t.Errorf("refresh by another client: status %d, want 400", status)
	}
}

// race sends the same request from several goroutines, all of which read the
// row before any of them claims it, and counts the 200s.
func (f *fixture) race(path string, form url.Values) int {
	const n = 8
	f.barrier.arm(n)
	defer f.barrier.arm(0)

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := f.postForm(path, form); status == http.StatusOK {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	return int(wins.Load())
}

// The identity provider sends the user back once per session.
func TestCallbackIsSingleUse(t *testing.T) {
	f := newFixture(t)
	_, reg := f.register(redirectURI)
	toIDP, _ := url.Parse(f.authorize(reg["client_id"].(string)).Header().Get("Location"))
	cb := "/oauth2/callback?" + url.Values{"code": {"idp-code"}, "state": {toIDP.Query().Get("state")}}.Encode()

	if rec := f.do(httptest.NewRequest(http.MethodGet, cb, nil)); rec.Code != http.StatusFound {
		t.Fatalf("first callback: status %d", rec.Code)
	}
	if rec := f.do(httptest.NewRequest(http.MethodGet, cb, nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("second callback: status %d, want 400", rec.Code)
	}
}

// Clients choose their own state and may repeat it or leave it out.
func TestRepeatedClientState(t *testing.T) {
	f := newFixture(t)
	_, reg := f.register(redirectURI)
	for i := range 2 {
		if rec := f.authorize(reg["client_id"].(string)); rec.Code != http.StatusFound {
			t.Errorf("authorize %d with a repeated state: status %d", i, rec.Code)
		}
	}
}

func TestMetadata(t *testing.T) {
	f := newFixture(t)
	var server, resource map[string]any
	json.Unmarshal(f.do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)).Body.Bytes(), &server)
	json.Unmarshal(f.do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)).Body.Bytes(), &resource)

	for key, want := range map[string]string{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
		"token_endpoint": issuer + "/token", "registration_endpoint": issuer + "/register",
	} {
		if server[key] != want {
			t.Errorf("%s = %v, want %s", key, server[key], want)
		}
	}
	if resource["resource"] != issuer || fmt.Sprint(resource["authorization_servers"]) != "["+issuer+"]" {
		t.Errorf("resource metadata = %v", resource)
	}
}

// memSecrets is the smallest correct SecretStore: the check and the write happen
// under one lock.
type memSecrets struct {
	mu    sync.Mutex
	value string
	calls int
}

func (m *memSecrets) LoadOrStoreSecret(ctx context.Context, candidate string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.value == "" {
		m.value = candidate
	}
	return m.value, nil
}

func TestLoadSecret(t *testing.T) {
	ctx := context.Background()
	store := &memSecrets{}

	// Instances starting together must all sign with the same secret
	results := make([]string, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret, err := mcpauth.LoadSecret(ctx, store)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = string(secret)
		}()
	}
	wg.Wait()
	for i, r := range results {
		if len(r) < 32 || r != results[0] {
			t.Fatalf("caller %d got a different or short secret (%d bytes)", i, len(r))
		}
	}

	// NewServer accepts what LoadSecret returns, and a later start gets it back
	again, err := mcpauth.LoadSecret(ctx, store)
	if err != nil || string(again) != results[0] {
		t.Errorf("second load: %v, same=%v", err, string(again) == results[0])
	}

	// A secret someone shortened by hand is refused, not used
	if _, err := mcpauth.LoadSecret(ctx, &memSecrets{value: "too-short"}); err == nil {
		t.Error("short stored secret accepted")
	}
	if _, err := mcpauth.LoadSecret(ctx, nil); err == nil {
		t.Error("nil store accepted")
	}

	failing := mcpauth.SecretStoreFunc(func(context.Context, string) (string, error) {
		return "", errors.New("database is down")
	})
	if _, err := mcpauth.LoadSecret(ctx, failing); err == nil {
		t.Error("store error swallowed")
	}
}
