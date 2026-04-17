package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/stretchr/testify/require"
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

func TestAPIKey_list_empty(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.List(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var result []any
	_ = json.NewDecoder(w.Body).Decode(&result)
	require.Len(t, result, 0)
}

func TestAPIKey_list_returnsKeys(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
	var result []map[string]any
	_ = json.NewDecoder(w.Body).Decode(&result)
	require.Len(t, result, 1)
	require.Equal(t, "k1", result[0]["id"])
}

func TestAPIKey_list_storeError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestAPIKey_create_success(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":"my-key"}`)

	require.Equal(t, http.StatusCreated, w.Code)
	// Full key should be returned only on creation.
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	key, ok := resp["key"].(string)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(key, "app_"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestAPIKey_create_missingName(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":""}`)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPIKey_create_nameTooLong(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, `{"name":"`+strings.Repeat("a", 101)+`"}`)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPIKey_create_storeError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAPIKey_create_invalidJSON(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Create(w, r)
	}, "not-json")

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestAPIKey_delete_success(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	req := httptest.NewRequest(http.MethodDelete, "/keys?id=k1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestAPIKey_delete_missingID(t *testing.T) {
	h := newAPIKeyHandler(&mockAPIKeyStore{})
	req := httptest.NewRequest(http.MethodDelete, "/keys", nil) // no id param
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPIKey_delete_notFound(t *testing.T) {
	store := &mockAPIKeyStore{
		deleteFunc: func(_ context.Context, _, _ string) error {
			return auth.ErrNotFound
		},
	}
	h := newAPIKeyHandler(store)
	req := httptest.NewRequest(http.MethodDelete, "/keys?id=unknown", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIKey_delete_storeError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}
