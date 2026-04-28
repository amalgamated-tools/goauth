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

| Endpoint | Status | Condition |
|---|---|---|
| `List` | 200 OK | Success |
| `List` | 500 Internal Server Error | Store failure |
| `Revoke` | 204 No Content | Success |
| `Revoke` | 400 Bad Request | Missing session ID |
| `Revoke` | 404 Not Found | Session not found or not owned by the authenticated user |
| `Revoke` | 500 Internal Server Error | Store failure |
| `RevokeAll` | 204 No Content | Success |
| `RevokeAll` | 500 Internal Server Error | Store failure |
