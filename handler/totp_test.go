package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mock TOTPStore
// ---------------------------------------------------------------------------

type mockTOTPStore struct {
	createFunc func(ctx context.Context, userID, secret string) (*auth.TOTPSecret, error)
	getFunc    func(ctx context.Context, userID string) (*auth.TOTPSecret, error)
	deleteFunc func(ctx context.Context, userID string) error
}

func (m *mockTOTPStore) CreateTOTPSecret(ctx context.Context, userID, secret string) (*auth.TOTPSecret, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, secret)
	}
	return &auth.TOTPSecret{ID: "totp-id", UserID: userID, Secret: secret, CreatedAt: time.Now()}, nil
}

func (m *mockTOTPStore) GetTOTPSecret(ctx context.Context, userID string) (*auth.TOTPSecret, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, userID)
	}
	return nil, auth.ErrTOTPNotFound
}

func (m *mockTOTPStore) DeleteTOTPSecret(ctx context.Context, userID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, userID)
	}
	return nil
}

// newTOTPHandler returns a TOTPHandler wired with mock stores.
func newTOTPHandler(totp auth.TOTPStore, users auth.UserStore) *TOTPHandler {
	return &TOTPHandler{
		TOTP:      totp,
		Users:     users,
		Issuer:    "TestApp",
		UsedCodes: &auth.TOTPUsedCodeCache{},
	}
}

// totpCode generates the current TOTP code for secret by delegating to the
// auth package, avoiding duplication of the HMAC-SHA1 algorithm here.
func totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := auth.GenerateTOTPCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

func TestTOTPStatusNotEnrolled(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/totp/status", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Status(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.False(t, resp["enrolled"])
}

func TestTOTPStatusEnrolled(t *testing.T) {
	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return &auth.TOTPSecret{ID: "totp-id", Secret: "SECRET"}, nil
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/totp/status", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Status(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.True(t, resp["enrolled"])
}

func TestTOTPStatusStoreError(t *testing.T) {
	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return nil, errors.New("db error")
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodGet, "/totp/status", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Status(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

func TestTOTPGenerateSuccess(t *testing.T) {
	users := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, Email: "alice@example.com"}, nil
		},
	}
	h := newTOTPHandler(&mockTOTPStore{}, users)
	req := httptest.NewRequest(http.MethodPost, "/totp/generate", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Generate(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp totpGenerateResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Secret)
	require.NotEmpty(t, resp.ProvisioningURI)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

func TestTOTPGenerateUserNotFound(t *testing.T) {
	users := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	h := newTOTPHandler(&mockTOTPStore{}, users)
	req := httptest.NewRequest(http.MethodPost, "/totp/generate", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Generate(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Enroll
// ---------------------------------------------------------------------------

func TestTOTPEnrollSuccess(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	code := totpCode(t, secret)

	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Enroll(w, r)
	}, `{"secret":"`+secret+`","code":"`+code+`"}`)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.True(t, resp["enrolled"])
}

func TestTOTPEnrollMissingFields(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	for _, body := range []string{
		`{"secret":"","code":"123456"}`,
		`{"secret":"ABCDEFGH","code":""}`,
	} {
		w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
			r = withUserID(r, "u1")
			h.Enroll(w, r)
		}, body)
		require.Equalf(t, http.StatusBadRequest, w.Code, "body %s", body)
	}
}

func TestTOTPEnrollInvalidSecret(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Enroll(w, r)
	}, `{"secret":"not-valid-base32!!!","code":"123456"}`)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTOTPEnrollWrongCode(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	// Craft a code that cannot be the current TOTP value by inverting the last digit.
	valid := totpCode(t, secret)
	last := valid[5] - '0'
	wrong := valid[:5] + fmt.Sprintf("%d", (last+1)%10)

	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Enroll(w, r)
	}, `{"secret":"`+secret+`","code":"`+wrong+`"}`)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTOTPEnrollStoreError(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	code := totpCode(t, secret)

	store := &mockTOTPStore{
		createFunc: func(_ context.Context, _, _ string) (*auth.TOTPSecret, error) {
			return nil, errors.New("db error")
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Enroll(w, r)
	}, `{"secret":"`+secret+`","code":"`+code+`"}`)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTOTPEnrollInvalidJSON(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Enroll(w, r)
	}, "not-json")

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func TestTOTPVerifySuccess(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	code := totpCode(t, secret)

	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return &auth.TOTPSecret{Secret: secret}, nil
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"`+code+`"}`)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.True(t, resp["valid"])
}

func TestTOTPVerifyReplayRejected(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	code := totpCode(t, secret)

	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return &auth.TOTPSecret{Secret: secret}, nil
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})

	// First use succeeds.
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code)

	// Immediate replay is rejected.
	w = postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTOTPVerifyReplayIndependentPerUser(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	code := totpCode(t, secret)

	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return &auth.TOTPSecret{Secret: secret}, nil
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})

	// u1 uses the code first.
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code)

	// u2 can still use the same code (independent replay cache per user).
	w = postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u2")
		h.Verify(w, r)
	}, `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestTOTPVerifyMissingCode(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":""}`)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTOTPVerifyNotEnrolled(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"123456"}`)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestTOTPVerifyNotEnrolledCustomError(t *testing.T) {
	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return nil, auth.ErrTOTPNotFound
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"123456"}`)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestTOTPVerifyStoreError(t *testing.T) {
	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return nil, errors.New("db error")
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"123456"}`)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTOTPVerifyWrongCode(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret()
	require.NoError(t, err)
	// Craft an invalid code.
	valid := totpCode(t, secret)
	last := valid[5] - '0'
	wrong := valid[:5] + fmt.Sprintf("%d", (last+1)%10)

	store := &mockTOTPStore{
		getFunc: func(_ context.Context, _ string) (*auth.TOTPSecret, error) {
			return &auth.TOTPSecret{Secret: secret}, nil
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, `{"code":"`+wrong+`"}`)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTOTPVerifyInvalidJSON(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	w := postJSON(t, func(w http.ResponseWriter, r *http.Request) {
		r = withUserID(r, "u1")
		h.Verify(w, r)
	}, "not-json")

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

func TestTOTPDisableSuccess(t *testing.T) {
	h := newTOTPHandler(&mockTOTPStore{}, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/totp", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Disable(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestTOTPDisableNotEnrolled(t *testing.T) {
	store := &mockTOTPStore{
		deleteFunc: func(_ context.Context, _ string) error {
			return auth.ErrTOTPNotFound
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/totp", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Disable(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestTOTPDisableNotEnrolledCustomError(t *testing.T) {
	store := &mockTOTPStore{
		deleteFunc: func(_ context.Context, _ string) error {
			return auth.ErrTOTPNotFound
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/totp", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Disable(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestTOTPDisableStoreError(t *testing.T) {
	store := &mockTOTPStore{
		deleteFunc: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	h := newTOTPHandler(store, &mockUserStore{})
	req := httptest.NewRequest(http.MethodDelete, "/totp", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Disable(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}
