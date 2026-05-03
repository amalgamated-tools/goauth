# OAuth2Handler — Generic OAuth2 Login

`OAuth2Handler` provides login, account linking, and session management for any OAuth2-based provider — GitHub, Discord, Slack, or any custom service. Unlike `OIDCHandler`, it does not require OIDC discovery or `id_token` verification. Instead, it delegates identity resolution to a pluggable `OAuth2IdentityProvider` that you implement (or use one of the built-ins).

!!! info "When to use OIDCHandler instead"
    If your provider supports OpenID Connect (Google, Microsoft, Okta, Auth0, Keycloak, etc.), prefer `OIDCHandler`. It performs standards-compliant `id_token` verification and provider discovery, and is more secure for those providers. Use `OAuth2Handler` only when the provider does not issue OIDC `id_token`s (e.g. GitHub).

## The OAuth2IdentityProvider interface

```go
type OAuth2IdentityProvider interface {
    FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error)
}

type OAuth2UserInfo struct {
    Subject       string // stable unique ID; use a provider prefix e.g. "github:12345"
    Email         string // must be non-empty
    Name          string // falls back to Email if empty
    EmailVerified bool
}
```

Implement `FetchUserInfo` for any provider by calling its user-profile API with the access token and mapping the response to `OAuth2UserInfo`. If the provider API call fails, return a non-nil error.

### Subject-prefix convention

Use a provider-specific prefix in `Subject` to avoid collisions across providers and with OIDC subjects:

```
github:12345
discord:987654321
slack:UXXXXXXXXX
```

Without a prefix, a GitHub user ID of `42` and a Discord user ID of `42` would resolve to the same `auth.User`, which is almost certainly wrong.

## Built-in providers

Two ready-to-use implementations are provided.

### GitHubProvider

Calls `GET /user` and `GET /user/emails` on the GitHub REST API. Subjects are prefixed `github:<id>`.

Required OAuth2 scopes: `read:user`, `user:email`.

```go
provider := &handler.GitHubProvider{HTTPClient: http.DefaultClient}
```

### GoogleOAuth2Provider

Calls the Google userinfo endpoint (`https://www.googleapis.com/oauth2/v3/userinfo`). Use this as a fallback for existing integrations; new Google integrations should prefer `OIDCHandler` with `https://accounts.google.com` as the issuer URL.

Required OAuth2 scope: `https://www.googleapis.com/auth/userinfo.email`.

```go
provider := &handler.GoogleOAuth2Provider{}
```

## Configuration

```go
h := &handler.OAuth2Handler{
    Users: userStore,
    JWT:   jwtMgr,
    OAuthConfig: oauth2.Config{
        ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        RedirectURL:  "https://myapp.example.com/auth/github/callback",
        Endpoint:     github.Endpoint, // from golang.org/x/oauth2/github
        Scopes:       []string{"read:user", "user:email"},
    },
    Provider:      &handler.GitHubProvider{},
    CookieName:    "session",
    SecureCookies: true,

    // Optional: enable server-side sessions and refresh-token rotation.
    Sessions:          sessionStore,
    RefreshTokenTTL:   handler.DefaultRefreshTokenTTL,
    RefreshCookieName: "refresh",

    // Optional: customise the post-login redirect query parameter.
    LoginRedirect: "github_login=1", // redirects to /?github_login=1
}

if err := h.Validate(); err != nil {
    log.Fatal(err)
}
```

!!! warning "Sessions requires RefreshCookieName"
    When `Sessions` is set, `RefreshCookieName` must also be non-empty. Because `Callback` delivers tokens via an HTTP redirect (no response body), the refresh token can only reach the client through an `HttpOnly` cookie. Call `h.Validate()` at server startup to catch this misconfiguration early.

## Routes

```
GET  /auth/github/login                  → h.Login              // redirect to provider
GET  /auth/github/callback               → h.Callback           // handle provider redirect
POST /auth/github/link-nonce             → h.CreateLinkNonce    // issue nonce (requires auth)
GET  /auth/github/link?nonce=<nonce>     → h.Link               // start link flow (requires auth)
```

## Response types

| Endpoint | HTTP status | Response body |
|---|---|---|
| `Login` | 302 Found | *(redirect to provider — no body)* |
| `Callback` | 302 Found | *(login: redirects to `/?<LoginRedirect>`; link: redirects to `/?oauth2_linked=true` — JWT and optional refresh token in `HttpOnly` cookies on the login path)* |
| `CreateLinkNonce` | 200 OK | `{"nonce": "<nonce>"}` |
| `Link` | 302 Found | *(redirect to provider — no body)* |

## Callback behaviour

The callback validates the CSRF state and PKCE verifier cookies, exchanges the authorisation code, and calls `Provider.FetchUserInfo`. It then handles three cases:

- **Existing subject** → log the user in
- **Existing email** → link the subject and log the user in (best-effort: if `LinkOIDCSubject` fails the failure is logged as a warning and login still succeeds)
- **New user** → create an account via `UserStore.CreateOIDCUser`

Concurrent first-login races (two requests creating the same account simultaneously) are handled by retrying the lookup when `CreateOIDCUser` returns `ErrEmailExists`.

`Callback` does **not** return JSON on success. It sets the JWT in an `HttpOnly` session cookie and redirects to `/?<LoginRedirect>` (HTTP 302).

### Email verification

For normal login flows, `FetchUserInfo` must return `EmailVerified: true`. The callback returns HTTP 401 `"OAuth2 email must be verified"` otherwise. The verification check is skipped during account-linking flows (the user is already authenticated).

## Account linking

The linking flow reuses `auth.OIDCLinkNonceStore` for nonce persistence and the same HMAC-signed state mechanism as `OIDCHandler`.

!!! info "Shared nonce storage"
    `OAuth2Handler` requires a `LinkNonces auth.OIDCLinkNonceStore` for account linking. In a multi-instance deployment the store must be backed by a shared external database. When `LinkNonces` is `nil`, `CreateLinkNonce` and `Link` return HTTP 503 `"account linking not configured"`. Register `linkNonceStore.DeleteExpiredLinkNonces` with `maintenance.StartCleanup` to prune stale entries.

### Link-callback redirect values

When the provider redirects back to `Callback` during a link flow, all outcomes are communicated via redirect query parameters.

On success the browser is redirected to `/?oauth2_linked=true`.

On failure the browser is redirected to `/?oauth2_link_error=<value>`:

| `oauth2_link_error` value | Cause |
|---|---|
| `User not found` | `FindByID` returned `ErrNotFound` for the link user |
| `Already linked` | The account already has an OIDC subject attached |
| `SSO identity linked to another account` | The incoming subject is already associated with a different account |
| `Link verification failed` | A database error was returned by `FindByID` (non-`ErrNotFound`) or by `FindByOIDCSubject` while checking for an existing subject association |
| `Failed to link` | `LinkOIDCSubject` returned an error after the duplicate-link check passed |

## Session tracking and refresh tokens

When `Sessions` is set:

- `Callback` creates a server-side session, embeds the session ID as the JWT `jti` claim, and sets an `HttpOnly` refresh token cookie (`RefreshCookieName`).
- The standard `auth.Middleware` validates the `jti` claim against the session store on each request.
- `RefreshCookieName` is required because `Callback` delivers tokens via a redirect, not a response body.

When `Sessions` is `nil`, only a stateless access JWT is issued. Token lifetime is determined by the `JWTManager` TTL.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `Login` | 302 Found | Redirect to OAuth2 provider |
| `Login` | 500 Internal Server Error | Failed to generate random state |
| `Callback` | 302 Found | Success — redirects to `/?<LoginRedirect>` |
| `Callback` | 400 Bad Request | Missing/invalid state cookie, PKCE verifier, or authorisation code |
| `Callback` | 401 Unauthorized | Provider error; code exchange failure; `FetchUserInfo` error; unverified email |
| `Callback` | 500 Internal Server Error | Failed to resolve/create user or issue tokens |
| `CreateLinkNonce` | 200 OK | `{"nonce": "..."}` |
| `CreateLinkNonce` | 500 Internal Server Error | Failed to generate or store nonce |
| `CreateLinkNonce` | 503 Service Unavailable | `LinkNonces` is `nil` |
| `Link` | 302 Found | Redirects to OAuth2 provider to start the linking flow |
| `Link` | 400 Bad Request | Missing nonce |
| `Link` | 401 Unauthorized | Invalid or expired nonce |
| `Link` | 409 Conflict | Account is already linked, or `Users.FindByID` returns `ErrNotFound` |
| `Link` | 500 Internal Server Error | Nonce store error or failed to initiate redirect |
| `Link` | 503 Service Unavailable | `LinkNonces` is `nil` |

!!! info "Link-callback redirects"
    After the provider returns to `Callback` during a link flow, outcomes that depend on the linking logic (duplicate subject check, `LinkOIDCSubject`) are communicated via redirect query parameters (`oauth2_link_error` / `oauth2_linked=true`). Early failures before identity is confirmed — such as missing cookies, a failed code exchange, or a `FetchUserInfo` error — still return JSON error responses.
