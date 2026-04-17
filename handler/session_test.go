package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/stretchr/testify/require"
)

func newSessionHandler(sessions auth.SessionStore) *SessionHandler {
	return &SessionHandler{
		Sessions: sessions,
		URLParamFunc: func(r *http.Request, key string) string {
			return r.URL.Query().Get(key)
		},
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestSessionListSuccess(t *testing.T) {
	now := time.Now()
	sessions := &mockSessionStore{
		listFunc: func(_ context.Context, userID string) ([]auth.Session, error) {
			return []auth.Session{
				{ID: "s1", UserID: userID, UserAgent: "Mozilla", IPAddress: "1.2.3.4", ExpiresAt: now.Add(time.Hour), CreatedAt: now},
				{ID: "s2", UserID: userID, UserAgent: "curl", IPAddress: "5.6.7.8", ExpiresAt: now.Add(2 * time.Hour), CreatedAt: now},
			}, nil
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var dtos []SessionDTO
	require.NoError(t, json.NewDecoder(w.Body).Decode(&dtos))
	require.Len(t, dtos, 2)
	require.Equal(t, "s1", dtos[0].ID)
	require.Equal(t, "s2", dtos[1].ID)
}

func TestSessionListEmpty(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var dtos []SessionDTO
	_ = json.NewDecoder(w.Body).Decode(&dtos)
	require.Empty(t, dtos)
}

func TestSessionListStoreError(t *testing.T) {
	sessions := &mockSessionStore{
		listFunc: func(_ context.Context, _ string) ([]auth.Session, error) {
			return nil, errors.New("db error")
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

func TestSessionRevokeSuccess(t *testing.T) {
	var revokedID string
	sessions := &mockSessionStore{
		deleteFunc: func(_ context.Context, id, _ string) error {
			revokedID = id
			return nil
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodDelete, "/sessions?id=sess-42", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Revoke(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, "sess-42", revokedID)
}

func TestSessionRevokeMissingID(t *testing.T) {
	h := newSessionHandler(&mockSessionStore{})

	req := httptest.NewRequest(http.MethodDelete, "/sessions", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Revoke(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	require.Equal(t, "session ID is required", body["error"])
}

func TestSessionRevokeNotFound(t *testing.T) {
	sessions := &mockSessionStore{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return auth.ErrNotFound
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodDelete, "/sessions?id=unknown", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Revoke(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestSessionRevokeStoreError(t *testing.T) {
	sessions := &mockSessionStore{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodDelete, "/sessions?id=sess-1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Revoke(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// RevokeAll
// ---------------------------------------------------------------------------

func TestSessionRevokeAllSuccess(t *testing.T) {
	var revokedUser string
	sessions := &mockSessionStore{
		deleteAllFunc: func(_ context.Context, userID string) error {
			revokedUser = userID
			return nil
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/all", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.RevokeAll(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, "u1", revokedUser)
}

func TestSessionRevokeAllStoreError(t *testing.T) {
	sessions := &mockSessionStore{
		deleteAllFunc: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/all", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.RevokeAll(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// toSessionDTO
// ---------------------------------------------------------------------------

func TestToSessionDTO(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := &auth.Session{
		ID:        "s1",
		UserID:    "u1",
		UserAgent: "Go-http-client/2.0",
		IPAddress: "192.168.1.1",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	dto := toSessionDTO(s)
	require.Equal(t, s.ID, dto.ID)
	require.Equal(t, s.UserAgent, dto.UserAgent)
	require.Equal(t, s.IPAddress, dto.IPAddress)
	require.True(t, dto.ExpiresAt.Equal(s.ExpiresAt))
	require.True(t, dto.CreatedAt.Equal(s.CreatedAt))
}
