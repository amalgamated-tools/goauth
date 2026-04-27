# SessionHandler — Session Management

`SessionHandler` lets authenticated users list their active sessions and revoke individual or all sessions remotely.

## Configuration

```go
h := &handler.SessionHandler{
    Sessions:     sessionStore,
    URLParamFunc: chi.URLParam,
}
```

## Routes

All routes require auth middleware.

```
GET    /sessions        → h.List       // list active sessions for the current user
DELETE /sessions/{id}   → h.Revoke     // revoke a specific session (204 No Content)
DELETE /sessions        → h.RevokeAll  // revoke all sessions for the current user (204 No Content)
```

## Response types

`List` returns a JSON array of `SessionDTO` objects:

```go
type SessionDTO struct {
    ID         string    `json:"id"`
    UserAgent  string    `json:"user_agent"`
    IPAddress  string    `json:"ip_address"`
    ExpiresAt  time.Time `json:"expires_at"`
    CreatedAt  time.Time `json:"created_at"`
}
```

The `id` field can be passed to `Revoke` to force a remote sign-out.

## HTTP status codes

| Endpoint | Success | Notable error codes |
|---|---|---|
| `List` | 200 OK | 401 (unauthenticated) |
| `Revoke` | 204 No Content | 400 (missing session ID), 404 (session not found or owned by another user) |
| `RevokeAll` | 204 No Content | 401 (unauthenticated) |
