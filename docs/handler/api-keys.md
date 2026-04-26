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
POST   /api-keys        → h.Create  // create key; raw key returned once, never again
DELETE /api-keys/{id}   → h.Delete
```

## Response types

`List` returns a JSON array of key metadata objects. `Create` returns the same shape plus a `key` field containing the full raw key (returned exactly once):

```go
// Returned by List (and by Create, which also includes Key)
type apiKeyDTO struct {
    ID         string     `json:"id"`
    Name       string     `json:"name"`
    KeyPrefix  string     `json:"key_prefix"` // configured prefix + first 12 hex chars of the random portion
    LastUsedAt *time.Time `json:"last_used_at"` // null until first use
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
