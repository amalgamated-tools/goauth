package handler

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

// SessionHandler holds dependencies for session management endpoints.
// URLParamFunc is a function that extracts a URL parameter by name from the
// request (e.g. chi.URLParam). This keeps the handler router-agnostic.
type SessionHandler struct {
	Sessions     auth.SessionStore
	URLParamFunc func(r *http.Request, key string) string
}

// SessionDTO is the public representation of an active session.
type SessionDTO struct {
	ID        string    `json:"id"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func toSessionDTO(s *auth.Session) SessionDTO {
	return SessionDTO{
		ID:        s.ID,
		UserAgent: s.UserAgent,
		IPAddress: s.IPAddress,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
}

// List returns all active sessions for the authenticated user.
func (h *SessionHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	sessions, err := h.Sessions.ListSessionsByUser(r.Context(), userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list sessions", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	dtos := make([]SessionDTO, len(sessions))
	for i := range sessions {
		dtos[i] = toSessionDTO(&sessions[i])
	}
	writeJSON(r.Context(), w, http.StatusOK, dtos)
}

// Revoke revokes a specific session by ID for the authenticated user.
func (h *SessionHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	id := h.URLParamFunc(r, "id")
	if id == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid session ID")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	if err := h.Sessions.DeleteSession(r.Context(), id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(r.Context(), w, http.StatusNotFound, "session not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to revoke session", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to revoke session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeAll revokes all sessions for the authenticated user.
func (h *SessionHandler) RevokeAll(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if err := h.Sessions.DeleteAllSessionsByUser(r.Context(), userID); err != nil {
		slog.ErrorContext(r.Context(), "failed to revoke all sessions", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to revoke sessions")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]string{"message": "all sessions revoked"})
}
