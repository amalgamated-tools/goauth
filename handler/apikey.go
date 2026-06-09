package handler

import (
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
	Logger       *slog.Logger
}

// Validate checks that the handler is correctly configured and returns an error
// when required dependencies are missing. Call Validate once at server startup
// so misconfiguration is caught immediately rather than at the first request.
func (h *APIKeyHandler) Validate() error {
	if err := requireField("APIKeyHandler", "APIKeys", h.APIKeys); err != nil {
		return err
	}
	return requireField("APIKeyHandler", "URLParamFunc", h.URLParamFunc)
}

// APIKeyDTO is the public representation of an API key.
type APIKeyDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type apiKeyCreateResponse struct {
	APIKeyDTO
	Key string `json:"key"`
}

// ToAPIKeyDTO converts an auth.APIKey to an APIKeyDTO.
func ToAPIKeyDTO(k *auth.APIKey) APIKeyDTO {
	return APIKeyDTO{
		ID: k.ID, Name: k.Name, KeyPrefix: k.KeyPrefix,
		LastUsedAt: k.LastUsedAt, CreatedAt: k.CreatedAt,
	}
}

// List returns all API keys for the authenticated user.
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	keys, err := h.APIKeys.ListAPIKeysByUser(r.Context(), userID)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to list API keys", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to list API keys")
		return
	}
	dtos := make([]APIKeyDTO, len(keys))
	for i := range keys {
		dtos[i] = ToAPIKeyDTO(&keys[i])
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
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to generate API key", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate API key")
		return
	}
	fullKey := h.Prefix + hexKey
	keyHash := auth.HashHighEntropyToken(fullKey)
	keyPrefix := h.Prefix + hexKey[:apiKeyDisplayPrefixHexLen]

	userID := auth.UserIDFromContext(r.Context())
	apiKey, err := h.APIKeys.CreateAPIKey(r.Context(), userID, req.Name, keyHash, keyPrefix)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to create API key", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	// Return the full key only on creation — it's never retrievable again.
	setNoCacheHeaders(w)
	writeJSON(r.Context(), w, http.StatusCreated, apiKeyCreateResponse{
		APIKeyDTO: ToAPIKeyDTO(apiKey),
		Key:       fullKey,
	})
}

// Delete removes an API key.
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	deleteUserResource(
		w,
		r,
		h.Logger,
		h.URLParamFunc,
		"invalid API key ID",
		"API key not found",
		"failed to delete API key",
		"failed to delete API key",
		h.APIKeys.DeleteAPIKey,
	)
}
