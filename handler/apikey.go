package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

const apiKeyDisplayPrefixHexLen = 12

// APIKeyHandler holds dependencies for API key endpoints.
// URLParamFunc is a function that extracts a URL parameter by name from the
// request (e.g. chi.URLParam). This keeps the handler router-agnostic.
type APIKeyHandler struct {
	APIKeys      auth.APIKeyStore
	Prefix       string // e.g. "bib_", "sch_"
	URLParamFunc func(r *http.Request, key string) string
}

type apiKeyDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type apiKeyCreateResponse struct {
	apiKeyDTO
	Key string `json:"key"`
}

func toAPIKeyDTO(k *auth.APIKey) apiKeyDTO {
	return apiKeyDTO{
		ID: k.ID, Name: k.Name, KeyPrefix: k.KeyPrefix,
		LastUsedAt: k.LastUsedAt, CreatedAt: k.CreatedAt,
	}
}

// List returns all API keys for the authenticated user.
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	keys, err := h.APIKeys.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list API keys", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to list API keys")
		return
	}
	dtos := make([]apiKeyDTO, len(keys))
	for i := range keys {
		dtos[i] = toAPIKeyDTO(&keys[i])
	}
	writeJSON(r.Context(), w, http.StatusOK, dtos)
}

// Create creates a new API key.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Name) > 100 {
		writeError(r.Context(), w, http.StatusBadRequest, "name must be 100 characters or fewer")
		return
	}

	// Generate 40 hex chars (20 bytes / 160 bits of entropy).
	hexKey, err := auth.GenerateRandomHex(20)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate API key")
		return
	}
	fullKey := h.Prefix + hexKey
	keyHash := auth.HashHighEntropyToken(fullKey)
	keyPrefix := h.Prefix + hexKey[:apiKeyDisplayPrefixHexLen]

	userID := auth.UserIDFromContext(r.Context())
	apiKey, err := h.APIKeys.CreateAPIKey(r.Context(), userID, req.Name, keyHash, keyPrefix)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to create API key", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	// Return the full key only on creation — it's never retrievable again.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(r.Context(), w, http.StatusCreated, apiKeyCreateResponse{
		apiKeyDTO: toAPIKeyDTO(apiKey),
		Key:       fullKey,
	})
}

// Delete removes an API key.
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := h.URLParamFunc(r, "id")
	if id == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid API key ID")
		return
	}
	userID := auth.UserIDFromContext(r.Context())

	if err := h.APIKeys.DeleteAPIKey(r.Context(), id, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "API key not found")
			return
		}
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to delete API key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
