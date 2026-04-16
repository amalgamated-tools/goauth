package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

func newAPIKeyHandler(store auth.APIKeyStore) *APIKeyHandler {
	return &APIKeyHandler{
		APIKeys: store,
		Prefix:  "app_",
		URLParamFunc: func(r *http.Request, key string) string {
			return r.URL.Query().Get(key)
		},
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestAPIKeyListEmpty(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result []any
	_ = json.NewDecoder(w.Body).Decode(&result)
	if len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestAPIKeyListReturnsKeys(t *testing.T) {
	now := time.Now()
	store := &mockAPIKeyStore{
		listFunc: func(_ context.Context, _ string) ([]auth.APIKey, error) {
			return []auth.APIKey{
				{ID: "k1", Name: "test", KeyPrefix: "app_abc", CreatedAt: now},
			}, nil
		},
	}
	h := newAPIKeyHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result []map[string]any
	_ = json.NewDecoder(w.Body).Decode(&result)
	if len(result) != 1 {
		t.Fatalf("expected 1 key, got %d", len(result))
	}
	if result[0]["id"] != "k1" {
		t.Errorf("expected id=k1, got %v", result[0]["id"])
	}
}

func TestAPIKeyListStoreError(t *testing.T) {
	store := &mockAPIKeyStore{
		listFunc: func(_ context.Context, _ string) ([]auth.APIKey, error) {
			return nil, errors.New("db error")
		},
	}
	h := newAPIKeyHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestAPIKeyCreateSuccess(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":"my-key"}`)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
	// Full key should be returned only on creation.
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	key, ok := resp["key"].(string)
	if !ok || !strings.HasPrefix(key, "app_") {
		t.Errorf("expected key starting with app_, got %v", resp["key"])
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("expected Cache-Control: no-store")
	}
}

func TestAPIKeyCreateMissingName(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":""}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIKeyCreateNameTooLong(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":"`+strings.Repeat("a", 101)+`"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIKeyCreateStoreError(t *testing.T) {
	store := &mockAPIKeyStore{
		createFunc: func(_ context.Context, _, _, _, _ string) (*auth.APIKey, error) {
			return nil, errors.New("db error")
		},
	}
	h := newAPIKeyHandler(store)
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":"my-key"}`)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAPIKeyCreateInvalidJSON(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, "not-json")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestAPIKeyDeleteSuccess(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	req := httptest.NewRequest(http.MethodDelete, "/keys?id=k1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestAPIKeyDeleteMissingID(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	req := httptest.NewRequest(http.MethodDelete, "/keys", nil) // no id param
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAPIKeyDeleteNotFound(t *testing.T) {
	store := &mockAPIKeyStore{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return sql.ErrNoRows
		},
	}
	h := newAPIKeyHandler(store)
	req := httptest.NewRequest(http.MethodDelete, "/keys?id=unknown", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAPIKeyDeleteStoreError(t *testing.T) {
	store := &mockAPIKeyStore{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	h := newAPIKeyHandler(store)
	req := httptest.NewRequest(http.MethodDelete, "/keys?id=k1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}
