package mcpauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	mcpauth "github.com/kabili207/go-mcp-auth"
)

const appURL = "https://app.example"

type browserFixture struct {
	t     *testing.T
	base  string
	idp   *fakeIDP
	users *users
	login *mcpauth.BrowserLogin
	mux   *http.ServeMux
}

func newBrowserFixture(t *testing.T) *browserFixture {
	return newBrowserFixtureAt(t, appURL, []byte(strings.Repeat("s", 32)))
}

func newBrowserFixtureAt(t *testing.T, baseURL string, secret []byte) *browserFixture {
	f := &browserFixture{t: t, base: baseURL, idp: newFakeIDP(t), users: &users{allowed: map[string]int{"sub-amy": 7}}}
	var err error
	f.login, err = mcpauth.NewBrowserLogin(context.Background(), mcpauth.BrowserConfig{
		BaseURL: baseURL,
		OIDC:    mcpauth.OIDCConfig{IssuerURL: f.idp.URL, ClientID: "web"},
		Users:   f.users,
		Secret:  secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mux = http.NewServeMux()
	f.login.Mount(f.mux)
	f.mux.Handle("/", f.login.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := mcpauth.IdentityFrom(r.Context())
		w.Write([]byte("user " + strconv.Itoa(id.User.(int))))
	})))
	return f
}

func (f *browserFixture) do(req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

// start begins a login and returns the state sent to the identity provider and
// the login cookie the browser now holds.
func (f *browserFixture) start(returnTo string) (string, *http.Cookie) {
	f.t.Helper()
	rec := f.do(httptest.NewRequest(http.MethodGet, appURL+"/auth/login?return="+url.QueryEscape(returnTo), nil))
	if rec.Code != http.StatusFound {
		f.t.Fatalf("login: got %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), f.idp.URL+"/authorize?") {
		f.t.Fatalf("login went to %s", loc)
	}
	q := loc.Query()
	if q.Get("redirect_uri") != f.base+"/auth/callback" || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "web" {
		f.t.Fatalf("authorize parameters: %v", q)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/auth/callback" {
		f.t.Fatalf("login cookie: %+v", cookies)
	}
	return q.Get("state"), cookies[0]
}

func (f *browserFixture) callback(state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return f.do(httptest.NewRequest(http.MethodGet, appURL+"/auth/callback?code=idp-code&state="+state, nil), cookies...)
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", rec.Result().Cookies())
	return nil
}

func (f *browserFixture) loggedIn() *http.Cookie {
	f.t.Helper()
	state, login := f.start("/")
	return sessionCookie(f.t, f.callback(state, login))
}

func page(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, appURL+path, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	return req
}

func TestBrowserLoginExtraScopes(t *testing.T) {
	f := newBrowserFixture(t)
	scopeAsked := func() string {
		rec := f.do(httptest.NewRequest(http.MethodGet, appURL+"/auth/login", nil))
		loc, _ := url.Parse(rec.Header().Get("Location"))
		return loc.Query().Get("scope")
	}
	if got := scopeAsked(); got != "openid profile email" {
		t.Errorf("default scope = %q", got)
	}

	var err error
	f.login, err = mcpauth.NewBrowserLogin(context.Background(), mcpauth.BrowserConfig{
		BaseURL: appURL,
		OIDC:    mcpauth.OIDCConfig{IssuerURL: f.idp.URL, ClientID: "web", ExtraScopes: []string{"groups"}},
		Users:   f.users,
		Secret:  []byte(strings.Repeat("s", 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mux = http.NewServeMux()
	f.login.Mount(f.mux)
	if got := scopeAsked(); got != "openid profile email groups" {
		t.Errorf("scope with groups = %q", got)
	}

	f.loggedIn()
	login := f.users.seen[len(f.users.seen)-1]
	if want := []string{"5f1c2a8e-0000-4000-8000-000000000001", "household@idm.example.com"}; !slices.Equal(login.Groups, want) {
		t.Errorf("groups at login = %v, want %v", login.Groups, want)
	}
}

func TestBrowserLoginRoundTrip(t *testing.T) {
	f := newBrowserFixture(t)

	rec := f.do(page("/bills?owner=me"))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/auth/login?return="+url.QueryEscape("/bills?owner=me") {
		t.Fatalf("logged out page: %d %s", rec.Code, rec.Header().Get("Location"))
	}

	state, login := f.start("/bills?owner=me")
	rec = f.callback(state, login)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/bills?owner=me" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	session := sessionCookie(t, rec)
	if !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" {
		t.Fatalf("session cookie flags: %+v", session)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == login.Name && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("login cookie was not cleared")
	}

	rec = f.do(page("/bills"), session)
	if rec.Code != http.StatusOK || rec.Body.String() != "user 7" {
		t.Fatalf("logged in page: %d %q", rec.Code, rec.Body.String())
	}
}

func TestBrowserLoginReturnStaysOnSite(t *testing.T) {
	f := newBrowserFixture(t)
	for _, returnTo := range []string{
		"https://evil.example/", "//evil.example/", "/\\evil.example/", "/\t/evil.example/",
		"javascript:alert(1)", "", "evil.example",
	} {
		state, login := f.start(returnTo)
		if loc := f.callback(state, login).Header().Get("Location"); loc != "/" {
			t.Errorf("return %q: sent to %q", returnTo, loc)
		}
	}
}

func TestBrowserCallbackNeedsItsOwnLoginCookie(t *testing.T) {
	f := newBrowserFixture(t)

	state, login := f.start("/")
	if rec := f.callback(state); rec.Code != http.StatusBadRequest {
		t.Errorf("no cookie: got %d", rec.Code)
	}

	otherState, _ := f.start("/")
	if rec := f.callback(otherState, &http.Cookie{Name: "session_login_" + otherState, Value: login.Value}); rec.Code != http.StatusBadRequest {
		t.Errorf("another attempt's cookie: got %d", rec.Code)
	}

	tampered := *login
	tampered.Value = login.Value[:len(login.Value)-2] + "xx"
	if rec := f.callback(state, &tampered); rec.Code != http.StatusBadRequest {
		t.Errorf("tampered cookie: got %d", rec.Code)
	}

	if rec := f.do(httptest.NewRequest(http.MethodGet, appURL+"/auth/callback?error=access_denied&error_description=<script>", nil)); rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "script") {
		t.Errorf("provider error: %d %q", rec.Code, rec.Body.String())
	}
}

func TestBrowserDeniedUserGetsNoSession(t *testing.T) {
	f := newBrowserFixture(t)
	f.users.deny("sub-amy")

	state, login := f.start("/")
	rec := f.callback(state, login)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			t.Fatal("denied user was given a session cookie")
		}
	}
}

func TestBrowserSessionEndsWhenUserIsDropped(t *testing.T) {
	f := newBrowserFixture(t)
	session := f.loggedIn()
	f.users.deny("sub-amy")
	if rec := f.do(page("/"), session); rec.Code != http.StatusFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestBrowserLoggedOutAPICallGets401(t *testing.T) {
	f := newBrowserFixture(t)
	for name, req := range map[string]*http.Request{
		"json": httptest.NewRequest(http.MethodGet, appURL+"/api/x", nil),
		"post": httptest.NewRequest(http.MethodPost, appURL+"/x", nil),
		"htmx": func() *http.Request { r := page("/x"); r.Header.Set("HX-Request", "true"); return r }(),
	} {
		if rec := f.do(req); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d", name, rec.Code)
		}
	}
}

// The session cookie and the MCP server's access tokens can share a secret and
// a base URL. Neither may stand in for the other.
func TestBrowserSessionAndAccessTokensAreNotInterchangeable(t *testing.T) {
	mcp := newFixture(t)
	f := newBrowserFixtureAt(t, issuer, mcp.secret)
	session := f.loggedIn()

	if id := mcp.server.ValidateToken(context.Background(), session.Value); id != nil {
		t.Error("session cookie accepted as an access token")
	}

	_, body := mcp.tokens()
	accessToken, _ := body["access_token"].(string)
	if mcp.server.ValidateToken(context.Background(), accessToken) == nil {
		t.Fatal("the access token is not valid to begin with")
	}
	if rec := f.do(page("/"), &http.Cookie{Name: "session", Value: accessToken}); rec.Code == http.StatusOK {
		t.Error("access token accepted as a session cookie")
	}

	_, login := f.start("/")
	if rec := f.do(page("/"), &http.Cookie{Name: "session", Value: login.Value}); rec.Code == http.StatusOK {
		t.Error("login cookie accepted as a session cookie")
	}
}

func TestBrowserRefusesCrossOriginWrites(t *testing.T) {
	f := newBrowserFixture(t)
	session := f.loggedIn()

	req := httptest.NewRequest(http.MethodPost, appURL+"/bills/1/paid", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := f.do(req, session); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, appURL+"/bills/1/paid", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if rec := f.do(req, session); rec.Code != http.StatusOK {
		t.Errorf("same-origin POST: got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, appURL+"/auth/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := f.do(req, session); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site logout: got %d", rec.Code)
	}
}

func TestBrowserLogout(t *testing.T) {
	f := newBrowserFixture(t)
	session := f.loggedIn()

	rec := f.do(httptest.NewRequest(http.MethodPost, appURL+"/auth/logout", nil), session)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].MaxAge >= 0 {
		t.Fatalf("logout cookies: %+v", cookies)
	}

	if rec := f.do(httptest.NewRequest(http.MethodGet, appURL+"/auth/logout", nil), session); rec.Code == http.StatusSeeOther {
		t.Error("GET logged out")
	}
}

func TestBrowserOptional(t *testing.T) {
	f := newBrowserFixture(t)
	h := f.login.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := mcpauth.IdentityFrom(r.Context()); id != nil {
			w.Write([]byte("hello " + id.Subject))
			return
		}
		w.Write([]byte("hello stranger"))
	}))

	for want, cookies := range map[string][]*http.Cookie{
		"hello stranger": nil,
		"hello sub-amy":  {f.loggedIn()},
	} {
		req := page("/")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Body.String() != want {
			t.Errorf("got %q, want %q", rec.Body.String(), want)
		}
	}
}

func TestNewBrowserLoginRefusesBadConfig(t *testing.T) {
	idp := newFakeIDP(t)
	good := mcpauth.BrowserConfig{
		BaseURL: appURL,
		OIDC:    mcpauth.OIDCConfig{IssuerURL: idp.URL, ClientID: "web"},
		Users:   &users{},
		Secret:  []byte(strings.Repeat("s", 32)),
	}
	for name, change := range map[string]func(*mcpauth.BrowserConfig){
		"path":         func(c *mcpauth.BrowserConfig) { c.BaseURL = appURL + "/app" },
		"no scheme":    func(c *mcpauth.BrowserConfig) { c.BaseURL = "app.example" },
		"short secret": func(c *mcpauth.BrowserConfig) { c.Secret = []byte("short") },
		"no client":    func(c *mcpauth.BrowserConfig) { c.OIDC.ClientID = "" },
		"no users":     func(c *mcpauth.BrowserConfig) { c.Users = nil },
	} {
		cfg := good
		change(&cfg)
		if _, err := mcpauth.NewBrowserLogin(context.Background(), cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
