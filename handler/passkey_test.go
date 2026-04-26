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
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mock PasskeyStore
// ---------------------------------------------------------------------------

type mockPasskeyStore struct {
	createChallengeFunc         func(ctx context.Context, userID *string, sessionData string, expiresAt time.Time) (*auth.PasskeyChallenge, error)
	getAndDeleteChallengeFunc   func(ctx context.Context, id string) (*auth.PasskeyChallenge, error)
	deleteExpiredChallengesFunc func(ctx context.Context) error
	createCredentialFunc        func(ctx context.Context, userID, name, credentialID, credentialData, aaguid string) (*auth.PasskeyCredential, error)
	listCredentialsByUserFunc   func(ctx context.Context, userID string) ([]auth.PasskeyCredential, error)
	findCredentialByCredIDFunc  func(ctx context.Context, credentialID string) (*auth.PasskeyCredential, error)
	findCredentialByIDAndUser   func(ctx context.Context, id, userID string) (*auth.PasskeyCredential, error)
	updateCredentialDataFunc    func(ctx context.Context, userID, credentialID, credentialData string) error
	deleteCredentialFunc        func(ctx context.Context, id, userID string) error
}

func (m *mockPasskeyStore) CreateChallenge(ctx context.Context, userID *string, sessionData string, expiresAt time.Time) (*auth.PasskeyChallenge, error) {
	if m.createChallengeFunc != nil {
		return m.createChallengeFunc(ctx, userID, sessionData, expiresAt)
	}
	return &auth.PasskeyChallenge{ID: "chal-id"}, nil
}
func (m *mockPasskeyStore) GetAndDeleteChallenge(ctx context.Context, id string) (*auth.PasskeyChallenge, error) {
	if m.getAndDeleteChallengeFunc != nil {
		return m.getAndDeleteChallengeFunc(ctx, id)
	}
	return nil, auth.ErrNotFound
}
func (m *mockPasskeyStore) DeleteExpiredChallenges(ctx context.Context) error {
	if m.deleteExpiredChallengesFunc != nil {
		return m.deleteExpiredChallengesFunc(ctx)
	}
	return nil
}
func (m *mockPasskeyStore) CreateCredential(ctx context.Context, userID, name, credentialID, credentialData, aaguid string) (*auth.PasskeyCredential, error) {
	if m.createCredentialFunc != nil {
		return m.createCredentialFunc(ctx, userID, name, credentialID, credentialData, aaguid)
	}
	return &auth.PasskeyCredential{ID: "cred-id", Name: name, AAGUID: aaguid}, nil
}
func (m *mockPasskeyStore) ListCredentialsByUser(ctx context.Context, userID string) ([]auth.PasskeyCredential, error) {
	if m.listCredentialsByUserFunc != nil {
		return m.listCredentialsByUserFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockPasskeyStore) FindCredentialByCredentialID(ctx context.Context, credentialID string) (*auth.PasskeyCredential, error) {
	if m.findCredentialByCredIDFunc != nil {
		return m.findCredentialByCredIDFunc(ctx, credentialID)
	}
	return nil, auth.ErrNotFound
}
func (m *mockPasskeyStore) FindCredentialByIDAndUser(ctx context.Context, id, userID string) (*auth.PasskeyCredential, error) {
	if m.findCredentialByIDAndUser != nil {
		return m.findCredentialByIDAndUser(ctx, id, userID)
	}
	return nil, auth.ErrNotFound
}
func (m *mockPasskeyStore) UpdateCredentialData(ctx context.Context, userID, credentialID, credentialData string) error {
	if m.updateCredentialDataFunc != nil {
		return m.updateCredentialDataFunc(ctx, userID, credentialID, credentialData)
	}
	return nil
}
func (m *mockPasskeyStore) DeleteCredential(ctx context.Context, id, userID string) error {
	if m.deleteCredentialFunc != nil {
		return m.deleteCredentialFunc(ctx, id, userID)
	}
	return nil
}

// newPasskeyHandler returns a PasskeyHandler with nil WebAuthn (not configured).
func newPasskeyHandler(passkeys auth.PasskeyStore, users auth.UserStore) *PasskeyHandler {
	return &PasskeyHandler{
		Users:      users,
		Passkeys:   passkeys,
		WebAuthn:   nil, // not configured
		JWT:        newTestJWT(),
		CookieName: "auth",
		URLParamFunc: func(r *http.Request, key string) string {
			return r.URL.Query().Get(key)
		},
	}
}

// ---------------------------------------------------------------------------
// Enabled
// ---------------------------------------------------------------------------

func TestPasskey_enabled_false(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/passkeys/enabled", nil)
	w := httptest.NewRecorder()
	h.Enabled(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.False(t, resp["enabled"])
}

// ---------------------------------------------------------------------------
// BeginRegistration / FinishRegistration / BeginAuthentication / FinishAuthentication
// — when WebAuthn is not configured these should return 503.
// ---------------------------------------------------------------------------

func TestPasskey_beginRegistration_notConfigured(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.BeginRegistration(w, r)
	}, `{"name":"my-passkey"}`)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestPasskey_finishRegistration_notConfigured(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodPost, "/passkeys/register/finish?session_id=abc", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.FinishRegistration(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestPasskey_finishRegistration_findByIDError(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	})
	require.NoError(t, err)

	challengeJSON := `{"session_data":{"challenge":"dGVzdA","rpId":"localhost","user_id":null,"expires":"2099-01-01T00:00:00Z","userVerification":""},"name":"test-key"}`
	store := &mockPasskeyStore{
		getAndDeleteChallengeFunc: func(_ context.Context, _ string) (*auth.PasskeyChallenge, error) {
			return &auth.PasskeyChallenge{
				ID:          "sess-1",
				SessionData: challengeJSON,
				ExpiresAt:   time.Now().Add(5 * time.Minute),
			}, nil
		},
	}
	users := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db unavailable")
		},
	}

	h := newPasskeyHandler(store, users)
	h.WebAuthn = wa

	req := httptest.NewRequest(http.MethodPost, "/passkeys/register/finish?session_id=sess-1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.FinishRegistration(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPasskey_beginRegistration_listCredentialsError(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	})
	require.NoError(t, err)

	store := &mockPasskeyStore{
		listCredentialsByUserFunc: func(_ context.Context, _ string) ([]auth.PasskeyCredential, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasskeyHandler(store, &mockUserStore{})
	h.WebAuthn = wa

	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.BeginRegistration(w, r)
	}, `{"name":"my-passkey"}`)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPasskey_finishRegistration_listCredentialsError(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	})
	require.NoError(t, err)

	challengeJSON := `{"session_data":{"challenge":"dGVzdA","rpId":"localhost","user_id":null,"expires":"2099-01-01T00:00:00Z","userVerification":""},"name":"test-key"}`
	store := &mockPasskeyStore{
		getAndDeleteChallengeFunc: func(_ context.Context, _ string) (*auth.PasskeyChallenge, error) {
			return &auth.PasskeyChallenge{
				ID:          "sess-1",
				SessionData: challengeJSON,
				ExpiresAt:   time.Now().Add(5 * time.Minute),
			}, nil
		},
		listCredentialsByUserFunc: func(_ context.Context, _ string) ([]auth.PasskeyCredential, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasskeyHandler(store, &mockUserStore{})
	h.WebAuthn = wa

	req := httptest.NewRequest(http.MethodPost, "/passkeys/register/finish?session_id=sess-1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.FinishRegistration(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPasskey_beginAuthentication_notConfigured(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodPost, "/passkeys/auth/begin", nil)
	w := httptest.NewRecorder()
	h.BeginAuthentication(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestPasskey_finishAuthentication_notConfigured(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodPost, "/passkeys/auth/finish?session_id=abc", nil)
	w := httptest.NewRecorder()
	h.FinishAuthentication(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ---------------------------------------------------------------------------
// ListCredentials
// ---------------------------------------------------------------------------

func TestPasskey_listCredentials_empty(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.ListCredentials(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var result []any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&result))
	require.Len(t, result, 0)
}

func TestPasskey_listCredentials_returnsItems(t *testing.T) {
	now := time.Now()
	store := &mockPasskeyStore{
		listCredentialsByUserFunc: func(_ context.Context, _ string) ([]auth.PasskeyCredential, error) {
			return []auth.PasskeyCredential{
				{ID: "cred-1", Name: "My Key", AAGUID: "aaguid-abc", CreatedAt: now},
			}, nil
		},
	}
	h := newPasskeyHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.ListCredentials(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var result []PasskeyCredentialDTO
	require.NoError(t, json.NewDecoder(w.Body).Decode(&result))
	require.Len(t, result, 1)
	require.Equal(t, "cred-1", result[0].ID)
	require.Equal(t, "My Key", result[0].Name)
}

func TestPasskey_listCredentials_storeError(t *testing.T) {
	store := &mockPasskeyStore{
		listCredentialsByUserFunc: func(_ context.Context, _ string) ([]auth.PasskeyCredential, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasskeyHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/passkeys", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.ListCredentials(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// DeleteCredential
// ---------------------------------------------------------------------------

func TestPasskey_deleteCredential_success(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/passkeys?id=cred-1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.DeleteCredential(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestPasskey_deleteCredential_missingID(t *testing.T) {
	h := newPasskeyHandler(&mockPasskeyStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/passkeys", nil) // no id
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.DeleteCredential(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasskey_deleteCredential_notFound(t *testing.T) {
	store := &mockPasskeyStore{
		deleteCredentialFunc: func(_ context.Context, _, _ string) error {
			return auth.ErrNotFound
		},
	}
	h := newPasskeyHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/passkeys?id=cred-1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.DeleteCredential(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasskey_deleteCredential_storeError(t *testing.T) {
	store := &mockPasskeyStore{
		deleteCredentialFunc: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	h := newPasskeyHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/passkeys?id=cred-1", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.DeleteCredential(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// loadWebAuthnCredentials
// ---------------------------------------------------------------------------

func TestLoadWebAuthnCredentials_empty(t *testing.T) {
	result := loadWebAuthnCredentials(context.Background(), nil)
	require.Len(t, result, 0)
}

func TestLoadWebAuthnCredentials_skipsCorrupted(t *testing.T) {
	creds := []auth.PasskeyCredential{
		{ID: "bad", CredentialData: "not valid json"},
	}
	result := loadWebAuthnCredentials(context.Background(), creds)
	require.Len(t, result, 0)
}
