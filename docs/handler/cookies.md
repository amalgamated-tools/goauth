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

## OIDC flow cookies

The OIDC flow uses two short-lived state cookies (`oidc_state` and `oidc_verifier`) that are set with `SameSite=Lax` instead of `Strict`. `SameSite=Lax` is required here because the OIDC provider redirects the browser back to your callback URL as a top-level cross-site navigation, which `SameSite=Strict` cookies would block. These cookies are `HttpOnly`, expire after 5 minutes, and are cleared immediately inside the callback handler.
