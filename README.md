# go-mcp-auth

An OAuth 2.1 authorization server for MCP endpoints, plus the bearer-token middleware that goes in front of them. It registers MCP clients dynamically (RFC 7591), sends the user to an external OpenID Connect provider to log in, and issues its own tokens for the MCP endpoint. That is what lets claude.ai and Claude Code connect to a self-hosted MCP server behind your own identity provider.

Extracted from Misty and Dev Memory, which carried forked copies of the same code.

## Wiring it up

```go
store, err := sqlitestore.New(ctx, db) // or pgstore.New(db)
secret, err := mcpauth.LoadSecret(ctx, settings) // see "The signing secret"

auth, err := mcpauth.NewServer(ctx, mcpauth.Config{
    Issuer:   "https://mail.example.com",
    Resource: "https://mail.example.com/mcp",
    OIDC: mcpauth.OIDCConfig{
        IssuerURL:    "https://idm.example.com/oauth2/openid/mail-mcp",
        ClientID:     "mail-mcp",
        DiscoveryURL: "https://idm.example.com/oauth2/openid/mail-mcp/.well-known/openid-configuration",
    },
    Store:     store,
    Users:     mcpauth.UserResolverFunc(resolveUser),
    JWTSecret: secret,
})

mux := http.NewServeMux()
auth.Mount(mux)
mux.Handle("/mcp", mcpauth.Middleware(auth.ResourceMetadataURL(), auth)(mcpHandler))
```

Behind the middleware, `mcpauth.IdentityFrom(r.Context())` returns the caller. Its `User` field is whatever your resolver returned.

Register `Issuer + "/oauth2/callback"` as a redirect URI on the client at your identity provider. The endpoint paths are fixed and sit at the root of `Issuer`. On a router other than `http.ServeMux`, register the `Handle*` methods yourself at the paths `Mount` uses.

## The signing secret

Access tokens are HS256 JWTs signed with `Config.JWTSecret`. It has to survive restarts, or every restart logs every client out. Where it lives is up to you: the library creates no storage for it.

If it comes from your config file or the environment, pass the bytes and you're done. If you'd rather have it generated once and kept in your database, implement `SecretStore` over whatever you already use for settings, and `LoadSecret` does the generate-once part:

```go
settings := mcpauth.SecretStoreFunc(func(ctx context.Context, candidate string) (string, error) {
    // Atomic: instances starting together must all end up with the same row.
    if _, err := db.ExecContext(ctx,
        `INSERT INTO settings (key, value) VALUES ('mcp_jwt_secret', $1) ON CONFLICT (key) DO NOTHING`,
        candidate); err != nil {
        return "", err
    }
    var secret string
    err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'mcp_jwt_secret'`).Scan(&secret)
    return secret, err
})
```

Anyone who can read the secret can mint access tokens for any user your resolver accepts, so give it the same care as the rest of that table.

## The user resolver

The library never learns what a user is in your application. It stores the identity provider's subject and asks you to resolve it:

```go
func resolveUser(ctx context.Context, c mcpauth.Claims) (any, error) {
    owner, ok := ownersBySubject[c.Subject]
    if !ok {
        return nil, fmt.Errorf("%w: no mailbox for %s", mcpauth.ErrUserDenied, c.Subject)
    }
    return owner, nil
}
```

It runs at login, where `Name` and `Email` are filled in and a new user can be created, and again on every request, where only `Subject` is set. Returning `ErrUserDenied` refuses the user with a 403 at login. Any error on a later request rejects the token, so a user you stop accepting loses access without waiting for their token to expire. Approval workflows, auto-provisioning and user ID types all stay on your side of this function.

## More than one kind of token

`Middleware` takes any number of validators and tries them in order. `Server` accepts the tokens it issued, `OIDCValidator` accepts tokens issued directly by the identity provider, and you can add your own for API keys:

```go
mcpauth.Middleware(auth.ResourceMetadataURL(), auth, oidcValidator, apiKeys)
```

Put `Server` first, so its own tokens are checked locally before anything else looks at them. `OIDCValidator` verifies JWTs against the provider's JWKS and refuses any that fail. It only asks the provider's userinfo endpoint about tokens that are not JWTs, because userinfo cannot say which client a token was issued for.

## Stores

`sqlitestore` uses `database/sql` only, so you pick the driver. It creates its own tables. Keep them in a database you do not treat as disposable: registered clients and refresh tokens live there.

`pgstore` uses the table layout Misty and Dev Memory already have, so moving either onto this library needs no data migration. `pgstore.Schema` is idempotent DDL to run from your own migrations.

Both have a `Secret` method that generates the JWT signing secret once and keeps it in the database. A secret generated per process invalidates every access token on every restart.

To write your own store, read the comment on `mcpauth.Store`. `MarkAuthCodeUsed` and `RevokeRefreshToken` must be compare-and-set and return `ErrAlreadyUsed` when they lose. An unconditional `UPDATE` lets two concurrent requests redeem one code, and lets a refresh token survive its own rotation.

## Who can register

Registration is anonymous and there is no consent page. An open redirect list would let anyone register a client pointing at their own host and collect a logged-in user's authorization code from one crafted link. So a redirect URI must be https on a host in `Config.AllowedRedirectHosts` (default `claude.ai` and `claude.com`) or on loopback, for native clients. The list is checked at registration and again at `/authorize`, which covers clients registered before the list existed.

## Differences from the code this replaces

For anyone porting Misty or Dev Memory:

- Access tokens carry `Resource` as their audience and it is checked. Tokens issued before the switch have the issuer as audience, so with `Resource` set to something else they are rejected once and the client refreshes.
- `OIDCValidator` requires `ClientID` in the token's audience when `ClientID` is set. Dev Memory did this and Misty did not.
- EC and RSA keys are both accepted, from `x5c` or from key parameters. Each app handled only some of these.
- The pending authorization is looked up and deleted by the state this server generated. The MCP client's own `state` can be empty or repeated, and used to be the key.
- The identity provider callback works once per session, whether or not it succeeds.
- An unknown `token_endpoint_auth_method` is rejected at registration.
- Token endpoint parameters are read from the body only, never the query string.
- The identity provider's `error_description` is logged, not shown to the user.
- `Issuer` and `Resource` come from config. Nothing is built from the `Host` or `X-Forwarded-Proto` headers.

## Tests

```
go test -race ./...
MCPAUTH_TEST_POSTGRES='postgres://...?sslmode=disable' go test ./pgstore
```

The Postgres test skips without a DSN.
