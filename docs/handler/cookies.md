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

All cookies are set with `HttpOnly` and `SameSite=Strict`. Pass `secure: true` in production to also set the `Secure` flag.
