# Cookie Helpers

The handler package exposes low-level cookie helpers for setting and clearing auth and refresh cookies. These are used internally by all handlers but are also available for custom flows.

## Auth cookie

```go
handler.SetAuthCookie(w, token, cookieName, secure)   // HttpOnly, SameSite=Strict
handler.ClearAuthCookie(w, cookieName, secure)
```

## Refresh cookie

```go
handler.SetRefreshCookie(w, token, cookieName, secure, maxAge) // HttpOnly, SameSite=Strict
handler.ClearRefreshCookie(w, cookieName, secure)
```

Auth and refresh cookies are set with `HttpOnly` and `SameSite=Strict`. Pass `secure: true` in production to also set the `Secure` flag.

## Token issuance flow

All handlers that issue tokens (`AuthHandler`, `MagicLinkHandler`, `OAuth2Handler`, `OIDCHandler`, `PasskeyHandler`) use a shared internal token issuance flow. When `Sessions` is non-nil, the flow:

1. Generates a 32-byte cryptographically random refresh token and hashes it for storage.
2. Creates a server-side session record (associating the hash, user agent, IP address, and expiry).
3. Creates a JWT with the session ID embedded as the `jti` claim via `CreateTokenWithSession`.
4. Sets the refresh token in an `HttpOnly` cookie using `SetRefreshCookie`.
5. Sets the access token in an `HttpOnly` cookie using `SetAuthCookie`.

When `Sessions` is nil, only token creation and step 5 apply — `CreateToken` is used instead (no `jti` claim) and no refresh cookie is set.

The `RefreshTokenTTL` field controls the refresh cookie `Max-Age` and session expiry. When unset (or ≤ 0), it defaults to `handler.DefaultRefreshTokenTTL` (7 days).

## OIDC flow cookies

The OIDC flow uses two short-lived state cookies (`oidc_state` and `oidc_verifier`) that are set with `SameSite=Lax` instead of `Strict`. `SameSite=Lax` is required here because the OIDC provider redirects the browser back to your callback URL as a top-level cross-site navigation, which `SameSite=Strict` cookies would block. These cookies are `HttpOnly`, expire after 5 minutes, and are cleared immediately inside the callback handler.

## OAuth2 flow cookies

The generic OAuth2 flow uses the same pattern: two short-lived state cookies (`oauth2_state` and `oauth2_verifier`) are set with `SameSite=Lax`, `HttpOnly`, and a 5-minute TTL. The rationale is identical — the OAuth2 provider redirects the browser back as a top-level cross-site navigation, which `SameSite=Strict` would block. Both cookies are cleared inside the callback handler after the CSRF state is validated and the verifier value has been read; the PKCE challenge is then verified server-side during the code exchange.
