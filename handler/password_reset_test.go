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

func newPasswordResetHandler(users auth.UserStore, resets auth.PasswordResetStore) *PasswordResetHandler {
	return &PasswordResetHandler{
		Users:  users,
		Resets: resets,
	}
}

// validResetStore returns a mockPasswordResetStore whose FindPasswordResetToken
// returns a non-expired token for the given userID.
func validResetStore(userID string) *mockPasswordResetStore {
	return &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return &auth.PasswordResetToken{
				ID:        "reset-id",
				UserID:    userID,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
}

// passwordUserStore returns a mockUserStore whose FindByID returns a user with
// a non-empty PasswordHash (i.e. password-auth-capable, not OIDC-only).
func passwordUserStore(userID string) *mockUserStore {
	return &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: userID, PasswordHash: "somehash"}, nil
		},
	}
}

// ---------------------------------------------------------------------------
// RequestReset
// ---------------------------------------------------------------------------

func TestRequestReset_success(t *testing.T) {
	emailSent := false
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{}
	h := newPasswordResetHandler(users, resets)
	h.SendResetEmail = func(_ context.Context, _, _ string) error {
		emailSent = true
		return nil
	}

	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, emailSent)
}

func TestRequestReset_unknownEmail(t *testing.T) {
	// Unknown email: FindByEmail returns auth.ErrNotFound — still 200.
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	resets := &mockPasswordResetStore{}
	h := newPasswordResetHandler(users, resets)
	emailSent := false
	h.SendResetEmail = func(_ context.Context, _, _ string) error {
		emailSent = true
		return nil
	}

	w := postJSON(t, h.RequestReset, `{"email":"unknown@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.False(t, emailSent)
}

func TestRequestReset_missingEmail(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, `{"email":""}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequestReset_invalidJSON(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, "not-json")
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequestReset_userStoreError(t *testing.T) {
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasswordResetHandler(users, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequestReset_createTokenError(t *testing.T) {
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.PasswordResetToken, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasswordResetHandler(users, resets)
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequestReset_sendEmailErrorStillOK(t *testing.T) {
	// A SendResetEmail failure should be logged and the orphaned token deleted,
	// but the HTTP response must still be 200 to avoid leaking account existence.
	tokenDeleted := false
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{
		deleteFunc: func(_ context.Context, _ string) error {
			tokenDeleted = true
			return nil
		},
	}
	h := newPasswordResetHandler(users, resets)
	h.SendResetEmail = func(_ context.Context, _, _ string) error {
		return errors.New("smtp error")
	}

	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, tokenDeleted)
}

func TestRequestReset_responseMessage(t *testing.T) {
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newPasswordResetHandler(users, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, `{"email":"any@test.com"}`)

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	require.NotEmpty(t, body["message"])
}

func TestRequestReset_nilSendResetEmail(t *testing.T) {
	// No SendResetEmail set — should not panic and should return 200.
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{}
	h := newPasswordResetHandler(users, resets) // SendResetEmail is nil

	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// ResetPassword
// ---------------------------------------------------------------------------

func TestResetPassword_success(t *testing.T) {
	users := passwordUserStore("u1")
	resets := validResetStore("u1")
	h := newPasswordResetHandler(users, resets)

	body := `{"token":"somerawtoken","newPassword":"newpassword123"}`
	w := postJSON(t, h.ResetPassword, body)
	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp["message"])
}

func TestResetPassword_missingToken(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.ResetPassword, `{"token":"","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_weakNewPassword(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"weak"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_invalidToken(t *testing.T) {
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return nil, auth.ErrInvalidToken
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"badtoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_expiredToken(t *testing.T) {
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return &auth.PasswordResetToken{
				ID:        "reset-id",
				UserID:    "u1",
				ExpiresAt: time.Now().Add(-time.Minute), // already expired
			}, nil
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"expiredtoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_findTokenStoreError(t *testing.T) {
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestResetPassword_updatePasswordStoreError(t *testing.T) {
	users := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: "somehash"}, nil
		},
		updatePasswordFunc: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	resets := validResetStore("u1")
	h := newPasswordResetHandler(users, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestResetPassword_deleteTokenErrorStillSucceeds(t *testing.T) {
	// Deletion failure after a successful password update should not cause an error response.
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return &auth.PasswordResetToken{
				ID:        "reset-id",
				UserID:    "u1",
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		deleteFunc: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	h := newPasswordResetHandler(passwordUserStore("u1"), resets)
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestResetPassword_invalidJSON(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	h.ResetPassword(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequestReset_tokenTTL(t *testing.T) {
	var capturedExpiresAt time.Time
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{
		createFunc: func(_ context.Context, _, _ string, expiresAt time.Time) (*auth.PasswordResetToken, error) {
			capturedExpiresAt = expiresAt
			return &auth.PasswordResetToken{ID: "reset-id"}, nil
		},
	}
	ttl := 30 * time.Minute
	h := &PasswordResetHandler{
		Users:    users,
		Resets:   resets,
		TokenTTL: ttl,
	}

	before := time.Now()
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	after := time.Now()

	require.Equal(t, http.StatusOK, w.Code)
	minExpiry := before.Add(ttl)
	maxExpiry := after.Add(ttl)
	require.False(t, capturedExpiresAt.Before(minExpiry) || capturedExpiresAt.After(maxExpiry))
}

func TestRequestReset_defaultTokenTTL(t *testing.T) {
	var capturedExpiresAt time.Time
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{
		createFunc: func(_ context.Context, _, _ string, expiresAt time.Time) (*auth.PasswordResetToken, error) {
			capturedExpiresAt = expiresAt
			return &auth.PasswordResetToken{ID: "reset-id"}, nil
		},
	}
	h := newPasswordResetHandler(users, resets) // TokenTTL is zero → defaults to 1 hour

	before := time.Now()
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	after := time.Now()

	require.Equal(t, http.StatusOK, w.Code)
	minExpiry := before.Add(defaultPasswordResetTTL)
	maxExpiry := after.Add(defaultPasswordResetTTL)
	require.False(t, capturedExpiresAt.Before(minExpiry) || capturedExpiresAt.After(maxExpiry))
}

func TestRequestReset_oidcOnlyUserSkipsToken(t *testing.T) {
	// OIDC-only accounts (empty PasswordHash) must not receive a reset token.
	tokenCreated := false
	emailSent := false
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "oidc@test.com", PasswordHash: ""}, nil
		},
	}
	resets := &mockPasswordResetStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.PasswordResetToken, error) {
			tokenCreated = true
			return &auth.PasswordResetToken{ID: "reset-id"}, nil
		},
	}
	h := newPasswordResetHandler(users, resets)
	h.SendResetEmail = func(_ context.Context, _, _ string) error {
		emailSent = true
		return nil
	}

	w := postJSON(t, h.RequestReset, `{"email":"oidc@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.False(t, tokenCreated)
	require.False(t, emailSent)
}

func TestRequestReset_rateLimited(t *testing.T) {
	rl := auth.NewRateLimiter(0, 1) // rate=0/sec, burst=1: first request passes, second is denied
	h := &PasswordResetHandler{
		Users:       &mockUserStore{},
		Resets:      &mockPasswordResetStore{},
		RateLimiter: rl,
	}
	postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`) // consumes the burst
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestResetPassword_expiredTokenSentinel(t *testing.T) {
	// ErrExpiredToken from the store must be treated as a client error (400),
	// not an internal server error.
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return nil, auth.ErrExpiredToken
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"expiredtoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_oidcOnlyUser(t *testing.T) {
	// Attempting to reset the password of an OIDC-only account must be rejected.
	users := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: ""}, nil
		},
	}
	resets := validResetStore("u1")
	h := newPasswordResetHandler(users, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"newpassword123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}
