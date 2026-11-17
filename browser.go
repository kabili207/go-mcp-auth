package mcpauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	loginPath           = "/auth/login"
	browserCallbackPath = "/auth/callback"
	logoutPath          = "/auth/logout"

	loginStateTTL        = 10 * time.Minute
	defaultSessionMaxAge = 30 * 24 * time.Hour
)

// BrowserConfig configures NewBrowserLogin.
type BrowserConfig struct {
	// BaseURL is the application's public URL, scheme and host only. The
	// identity provider must have BaseURL + "/auth/callback" as a redirect URI.
	// Cookies are marked Secure when it is https.
	BaseURL string

	OIDC  OIDCConfig
	Users UserResolver

	// Secret signs the cookies, and must be at least 32 bytes. It can be the
	// same as Config.JWTSecret: the signing key is derived from it, so a
	// session cookie is never accepted as an access token or the reverse.
	Secret []byte

	// CookieName is the session cookie's name. Default "session".
	CookieName string
	// MaxAge is how long a login lasts. Default 30 days.
	MaxAge time.Duration
}

// BrowserLogin logs people in through the identity provider and keeps them
// logged in with a signed cookie. It needs no Server and no Store, so it also
// serves applications with no MCP endpoint.
//
// There is no session table. The user resolver runs on every request instead,
// so someone the host stops accepting is locked out at once. What a cookie
// cannot do is be revoked on its own: logging out removes it from the browser,
// and a copy taken earlier stays valid until MaxAge.
type BrowserLogin struct {
	cfg        BrowserConfig
	baseURL    string
	key        []byte
	secure     bool
	discovery  Discovery
	httpClient *http.Client
	csrf       *http.CrossOriginProtection
}

type sessionClaims struct {
	jwt.RegisteredClaims
}

// loginClaims carries one login attempt from /auth/login to the callback. Its
// ID is the state sent to the identity provider.
type loginClaims struct {
	jwt.RegisteredClaims
	Verifier string `json:"verifier"`
	Return   string `json:"return"`
}

// NewBrowserLogin performs OIDC discovery, so it fails if the provider is
// unreachable.
func NewBrowserLogin(ctx context.Context, cfg BrowserConfig) (*BrowserLogin, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("base URL must be an http or https URL")
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		// The handlers sit at fixed paths from the root, and so do the cookies
		return nil, errors.New("base URL must have no path")
	}
	if cfg.OIDC.ClientID == "" {
		return nil, errors.New("OIDC client ID is required")
	}
	if cfg.Users == nil {
		return nil, errors.New("user resolver is required")
	}
	if len(cfg.Secret) < 32 {
		return nil, errors.New("secret must be at least 32 bytes")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaultSessionMaxAge
	}

	client := &http.Client{Timeout: idpTimeout}
	discovery, err := discover(ctx, client, cfg.OIDC)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	mac := hmac.New(sha256.New, cfg.Secret)
	mac.Write([]byte("mcpauth browser login"))

	return &BrowserLogin{
		cfg:        cfg,
		baseURL:    u.Scheme + "://" + u.Host,
		key:        mac.Sum(nil),
		secure:     u.Scheme == "https",
		discovery:  discovery,
		httpClient: client,
		csrf:       http.NewCrossOriginProtection(),
	}, nil
}

// Mount registers the login, callback and logout endpoints at the root of mux.
func (b *BrowserLogin) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+loginPath, b.HandleLogin)
	mux.HandleFunc("GET "+browserCallbackPath, b.HandleCallback)
	mux.Handle("POST "+logoutPath, b.csrf.Handler(http.HandlerFunc(b.HandleLogout)))
}

// HandleLogin sends the browser to the identity provider. The return query
// parameter is where it comes back to afterwards, and must be a path on this
// site.
func (b *BrowserLogin) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomHex(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	verifier, err := randomHex(32)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	attempt, err := b.sign(loginClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    b.baseURL,
			Audience:  jwt.ClaimStrings{b.baseURL + loginPath},
			ExpiresAt: jwt.NewNumericDate(now.Add(loginStateTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        state,
		},
		Verifier: verifier,
		Return:   localPath(r.URL.Query().Get("return")),
	})
	if err != nil {
		slog.Error("browser login: failed to sign login state", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	// One cookie per attempt, named by its state, so logins started in two
	// tabs do not overwrite each other.
	http.SetCookie(w, &http.Cookie{
		Name:     b.loginCookie(state),
		Value:    attempt,
		Path:     browserCallbackPath,
		MaxAge:   int(loginStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   b.secure,
		SameSite: http.SameSiteLaxMode,
	})

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", b.cfg.OIDC.ClientID)
	params.Set("redirect_uri", b.baseURL+browserCallbackPath)
	params.Set("scope", b.cfg.OIDC.scope())
	params.Set("state", state)
	params.Set("code_challenge", s256Challenge(verifier))
	params.Set("code_challenge_method", "S256")
	http.Redirect(w, r, b.discovery.AuthorizationEndpoint+"?"+params.Encode(), http.StatusFound)
}

// HandleCallback receives the browser back from the identity provider and
// starts the session.
func (b *BrowserLogin) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	if errorParam := q.Get("error"); errorParam != "" {
		slog.Warn("browser login: identity provider returned an error", "error", errorParam, "description", q.Get("error_description"))
		http.Error(w, "Login failed", http.StatusBadRequest)
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(b.loginCookie(state))
	if err != nil {
		http.Error(w, "Login expired or already used, please try again", http.StatusBadRequest)
		return
	}
	// One attempt per login, whatever happens next
	b.clearCookie(w, cookie.Name, browserCallbackPath)

	attempt := &loginClaims{}
	if !b.parse(cookie.Value, attempt, loginPath) || !constantTimeEqual(attempt.ID, state) {
		http.Error(w, "Login expired or already used, please try again", http.StatusBadRequest)
		return
	}

	idpToken, err := exchangeIDPCode(ctx, b.httpClient, b.cfg.OIDC, b.discovery, code, attempt.Verifier, b.baseURL+browserCallbackPath)
	if err != nil {
		slog.Error("browser login: identity provider token exchange failed", "error", err)
		http.Error(w, "Failed to complete login", http.StatusInternalServerError)
		return
	}
	claims, err := fetchUserinfo(ctx, b.httpClient, b.discovery.UserinfoEndpoint, idpToken)
	if err != nil {
		slog.Error("browser login: failed to get user info", "error", err)
		http.Error(w, "Failed to retrieve user information", http.StatusInternalServerError)
		return
	}
	claims.Issuer = b.discovery.Issuer

	if _, err := b.cfg.Users.ResolveUser(ctx, *claims); err != nil {
		if errors.Is(err, ErrUserDenied) {
			slog.Warn("browser login: user denied", "subject", claims.Subject, "error", err)
			http.Error(w, "This account is not allowed to use this service", http.StatusForbidden)
			return
		}
		slog.Error("browser login: failed to resolve user", "subject", claims.Subject, "error", err)
		http.Error(w, "Failed to look up user account", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	session, err := b.sign(sessionClaims{jwt.RegisteredClaims{
		Issuer:    b.baseURL,
		Subject:   claims.Subject,
		Audience:  jwt.ClaimStrings{b.baseURL + "/auth/session"},
		ExpiresAt: jwt.NewNumericDate(now.Add(b.cfg.MaxAge)),
		IssuedAt:  jwt.NewNumericDate(now),
	}})
	if err != nil {
		slog.Error("browser login: failed to sign session", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     b.cfg.CookieName,
		Value:    session,
		Path:     "/",
		MaxAge:   int(b.cfg.MaxAge.Seconds()),
		HttpOnly: true,
		Secure:   b.secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, attempt.Return, http.StatusSeeOther)
}

// HandleLogout removes the session cookie. It is POST only, and Mount puts it
// behind the same cross-origin check as Require.
func (b *BrowserLogin) HandleLogout(w http.ResponseWriter, r *http.Request) {
	b.clearCookie(w, b.cfg.CookieName, "/")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Require lets through only requests with a session, and puts the caller in
// the context for IdentityFrom. Without one, a browser asking for a page is
// sent to log in and anything else gets a 401.
//
// It also refuses cross-origin POST, PUT, PATCH and DELETE requests, which is
// the CSRF protection for whatever it wraps.
func (b *BrowserLogin) Require(next http.Handler) http.Handler {
	return b.csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := b.identity(r)
		if id == nil {
			if wantsPage(r) {
				http.Redirect(w, r, loginPath+"?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			http.Error(w, "Login required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	}))
}

// Optional is Require for pages anyone can see that change for someone logged
// in. IdentityFrom returns nil when nobody is.
func (b *BrowserLogin) Optional(next http.Handler) http.Handler {
	return b.csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := b.identity(r); id != nil {
			r = r.WithContext(WithIdentity(r.Context(), id))
		}
		next.ServeHTTP(w, r)
	}))
}

// identity resolves the user again on every request, as Server does for its
// access tokens.
func (b *BrowserLogin) identity(r *http.Request) *Identity {
	cookie, err := r.Cookie(b.cfg.CookieName)
	if err != nil {
		return nil
	}
	claims := &sessionClaims{}
	if !b.parse(cookie.Value, claims, "/auth/session") || claims.Subject == "" {
		return nil
	}
	user, err := b.cfg.Users.ResolveUser(r.Context(), Claims{Subject: claims.Subject, Issuer: b.discovery.Issuer})
	if err != nil {
		slog.Warn("browser login: session refused by user resolver", "subject", claims.Subject, "error", err)
		return nil
	}
	return &Identity{Subject: claims.Subject, User: user}
}

func (b *BrowserLogin) sign(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(b.key)
}

// parse checks the signature, expiry and that the token was minted here for
// audiencePath, which keeps a login cookie from passing as a session.
func (b *BrowserLogin) parse(value string, claims jwt.Claims, audiencePath string) bool {
	token, err := jwt.ParseWithClaims(value, claims, func(*jwt.Token) (any, error) {
		return b.key, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(b.baseURL),
		jwt.WithAudience(b.baseURL+audiencePath),
		jwt.WithExpirationRequired(),
	)
	return err == nil && token.Valid
}

func (b *BrowserLogin) loginCookie(state string) string {
	return b.cfg.CookieName + "_login_" + state
}

func (b *BrowserLogin) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   b.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// wantsPage tells a browser navigating to a page, which can be sent to log in,
// from a script or API client, which needs a status it can act on. htmx asks
// for HTML too but swaps the response into the page, so it gets the 401.
func wantsPage(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") &&
		r.Header.Get("HX-Request") == ""
}

// localPath returns s if it is a path on this site and "/" otherwise. A
// browser reads "//host" and "/\host" as another site, and drops tabs and
// newlines before deciding, so anything with a backslash or a control
// character is refused outright.
func localPath(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return "/"
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	return s
}
