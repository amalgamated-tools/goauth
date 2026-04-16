package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var dtos []SessionDTO
	if err := json.NewDecoder(w.Body).Decode(&dtos); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dtos) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(dtos))
	}
	if dtos[0].ID != "s1" || dtos[1].ID != "s2" {
		t.Errorf("unexpected session IDs: %v", dtos)
	}
}

func TestSessionListEmpty(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var dtos []SessionDTO
	_ = json.NewDecoder(w.Body).Decode(&dtos)
	if len(dtos) != 0 {
		t.Errorf("expected empty list, got %v", dtos)
	}
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

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
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

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if revokedID != "sess-42" {
		t.Errorf("expected revokedID %q, got %q", "sess-42", revokedID)
	}
}

func TestSessionRevokeMissingID(t *testing.T) {
	h := newSessionHandler(&mockSessionStore{})

	req := httptest.NewRequest(http.MethodDelete, "/sessions", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Revoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSessionRevokeNotFound(t *testing.T) {
	sessions := &mockSessionStore{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return sql.ErrNoRows
		},
	}
	h := newSessionHandler(sessions)

	req := httptest.NewRequest(http.MethodDelete, "/sessions?id=unknown", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Revoke(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
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

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if revokedUser != "u1" {
		t.Errorf("expected revokedUser %q, got %q", "u1", revokedUser)
	}
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

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
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
	if dto.ID != s.ID {
		t.Errorf("ID: expected %q, got %q", s.ID, dto.ID)
	}
	if dto.UserAgent != s.UserAgent {
		t.Errorf("UserAgent: expected %q, got %q", s.UserAgent, dto.UserAgent)
	}
	if dto.IPAddress != s.IPAddress {
		t.Errorf("IPAddress: expected %q, got %q", s.IPAddress, dto.IPAddress)
	}
	if !dto.ExpiresAt.Equal(s.ExpiresAt) {
		t.Errorf("ExpiresAt: expected %v, got %v", s.ExpiresAt, dto.ExpiresAt)
	}
	if !dto.CreatedAt.Equal(s.CreatedAt) {
		t.Errorf("CreatedAt: expected %v, got %v", s.CreatedAt, dto.CreatedAt)
	}
}
