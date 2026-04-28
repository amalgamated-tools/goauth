# APIKeyHandler — API Keys

`APIKeyHandler` manages API key lifecycle: creation, listing, and deletion. Keys are 160-bit random values prefixed with the configured string. Only the SHA-256 hash is persisted — the raw key is returned in the creation response only.

## Configuration

```go
h := &handler.APIKeyHandler{
    APIKeys:      apiKeyStore,
    Prefix:       "myapp_",   // prepended to the random hex token
    URLParamFunc: chi.URLParam,
}
```

## Routes

All routes require auth middleware.

```
GET    /api-keys        → h.List    // list keys (prefix + metadata only, never the raw key)
POST   /api-keys        → h.Create  // 201 Created; raw key returned once, never again
DELETE /api-keys/{id}   → h.Delete  // 204 No Content
```

### Create request body

```json
{"name": "CI pipeline key"}
```

`name` is required and must be 100 characters or fewer.

## Response types

`List` returns a JSON array of key metadata objects. `Create` returns the same shape plus a `key` field containing the full raw key (returned exactly once):

```go
// Returned by List (and by Create, which also includes Key)
type apiKeyDTO struct {
    ID         string     `json:"id"`
    Name       string     `json:"name"`
    KeyPrefix  string     `json:"key_prefix"` // configured prefix + first 12 hex chars of the random portion
    LastUsedAt *time.Time `json:"last_used_at"` // null until first use; see note below
    CreatedAt  time.Time  `json:"created_at"`
}

// Returned by Create only
type apiKeyCreateResponse struct {
    apiKeyDTO
    Key string `json:"key"` // full raw API key; present in Create response only
}
```

!!! warning "Store the key immediately"
    The raw API key is returned once in the `Create` response and cannot be recovered. Store it securely before closing the creation response.

The `Create` response also sets `Cache-Control: no-store` and `Pragma: no-cache` to prevent the raw key from being stored in browser or proxy caches.

!!! note "`last_used_at` update throttle"
    The middleware updates `last_used_at` at most once every **5 minutes** per key ID (within a single process) to reduce database write pressure. The value may therefore lag behind real usage by up to 5 minutes. See [API key `last_used_at` update throttle](../auth/middleware.md#api-key-last_used_at-update-throttle) for details.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `List` | 200 OK | Success |
| `List` | 500 Internal Server Error | Store failure |
| `Create` | 201 Created | Success |
| `Create` | 400 Bad Request | Missing or empty `name`; `name` exceeds 100 characters |
| `Create` | 500 Internal Server Error | API key generation failure or store failure |
| `Delete` | 204 No Content | Success |
| `Delete` | 400 Bad Request | Missing key ID |
| `Delete` | 404 Not Found | API key not found or not owned by the authenticated user |
| `Delete` | 500 Internal Server Error | Store failure |
