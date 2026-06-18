# Cookie Helpers

The handler package exposes low-level cookie helpers for setting and clearing auth and refresh cookies. These are used internally by all handlers but are also available for custom flows.

All cookie helpers share the same base attributes via a private `setCookie` helper:

| Attribute | Value |
|---|---|
| `Path` | `"/"` |
| `HttpOnly` | `true` |
| `SameSite` | `Strict` |
| `Secure` | caller-controlled |

## Auth cookie

```go
handler.SetAuthCookie(w, token, cookieName, secure)
handler.ClearAuthCookie(w, cookieName, secure)
```

`SetAuthCookie` sets `MaxAge: 0`, which creates a **session cookie** — the browser discards it when the session ends (tab or window closes). Use this for short-lived access tokens whose lifetime is already bounded by the JWT expiry.

`ClearAuthCookie` sets `MaxAge: -1` to instruct the browser to delete the cookie immediately.

## Refresh cookie

```go
handler.SetRefreshCookie(w, token, cookieName, secure, maxAge)
handler.ClearRefreshCookie(w, cookieName, secure)
```

`SetRefreshCookie` accepts an explicit `maxAge` (in seconds) so the refresh cookie persists across browser sessions. Pass the `RefreshTokenTTL` value (converted to seconds) for consistent expiry between the cookie and the server-side session record.

`ClearRefreshCookie` sets `MaxAge: -1` to delete the cookie immediately.

Pass `secure: true` in production to also set the `Secure` flag on all cookies.

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

The OIDC flow uses three short-lived cookies (`oidc_state`, `oidc_verifier`, and `oidc_nonce`) that are set with `SameSite=Lax` instead of `SameSite=Strict`. `SameSite=Lax` is required here because the OIDC provider redirects the browser back to your callback URL as a top-level cross-site navigation, which `SameSite=Strict` cookies would block.

`oidc_state` provides CSRF protection. `oidc_verifier` enables PKCE replay protection. `oidc_nonce` prevents ID token replay attacks by tying the authorization request to the returned `id_token`.

All three cookies are `HttpOnly`, expire after 5 minutes, and are cleared immediately inside the callback handler.

## OAuth2 flow cookies

The generic OAuth2 flow uses the same pattern: two short-lived state cookies (`oauth2_state` and `oauth2_verifier`) are set with `SameSite=Lax`, `HttpOnly`, and a 5-minute TTL. The rationale is identical — the OAuth2 provider redirects the browser back as a top-level cross-site navigation, which `SameSite=Strict` would block. Both cookies are cleared inside the callback handler after the CSRF state is validated and the verifier value has been read; the PKCE challenge is then verified server-side during the code exchange.
