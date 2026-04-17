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

func TestRequestResetSuccess(t *testing.T) {
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if !emailSent {
		t.Error("expected SendResetEmail to be called")
	}
}

func TestRequestResetUnknownEmail(t *testing.T) {
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for unknown email, got %d", w.Code)
	}
	if emailSent {
		t.Error("expected SendResetEmail NOT to be called for unknown email")
	}
}

func TestRequestResetMissingEmail(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, `{"email":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRequestResetInvalidJSON(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRequestResetUserStoreError(t *testing.T) {
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasswordResetHandler(users, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRequestResetCreateTokenError(t *testing.T) {
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
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRequestResetSendEmailErrorStillOK(t *testing.T) {
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even when SendResetEmail fails, got %d", w.Code)
	}
	if !tokenDeleted {
		t.Error("expected orphaned token to be deleted after email failure")
	}
}

func TestRequestResetResponseMessage(t *testing.T) {
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newPasswordResetHandler(users, &mockPasswordResetStore{})
	w := postJSON(t, h.RequestReset, `{"email":"any@test.com"}`)

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["message"] == "" {
		t.Error("expected non-empty message in response")
	}
}

func TestRequestResetNilSendResetEmail(t *testing.T) {
	// No SendResetEmail set — should not panic and should return 200.
	users := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: "somehash"}, nil
		},
	}
	resets := &mockPasswordResetStore{}
	h := newPasswordResetHandler(users, resets) // SendResetEmail is nil

	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ResetPassword
// ---------------------------------------------------------------------------

func TestResetPasswordSuccess(t *testing.T) {
	users := passwordUserStore("u1")
	resets := validResetStore("u1")
	h := newPasswordResetHandler(users, resets)

	body := `{"token":"somerawtoken","newPassword":"newpassword123"}`
	w := postJSON(t, h.ResetPassword, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] == "" {
		t.Error("expected non-empty message in response")
	}
}

func TestResetPasswordMissingToken(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.ResetPassword, `{"token":"","newPassword":"newpassword123"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestResetPasswordWeakNewPassword(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"weak"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestResetPasswordInvalidToken(t *testing.T) {
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return nil, auth.ErrInvalidToken
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"badtoken","newPassword":"newpassword123"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestResetPasswordExpiredToken(t *testing.T) {
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
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired token, got %d", w.Code)
	}
}

func TestResetPasswordFindTokenStoreError(t *testing.T) {
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return nil, errors.New("db error")
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"newpassword123"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestResetPasswordUpdatePasswordStoreError(t *testing.T) {
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
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestResetPasswordDeleteTokenErrorStillSucceeds(t *testing.T) {
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even when token deletion fails, got %d", w.Code)
	}
}

func TestResetPasswordInvalidJSON(t *testing.T) {
	h := newPasswordResetHandler(&mockUserStore{}, &mockPasswordResetStore{})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	h.ResetPassword(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRequestResetTokenTTL(t *testing.T) {
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	minExpiry := before.Add(ttl)
	maxExpiry := after.Add(ttl)
	if capturedExpiresAt.Before(minExpiry) || capturedExpiresAt.After(maxExpiry) {
		t.Errorf("expiresAt %v not in expected range [%v, %v]", capturedExpiresAt, minExpiry, maxExpiry)
	}
}

func TestRequestResetDefaultTokenTTL(t *testing.T) {
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	minExpiry := before.Add(defaultPasswordResetTTL)
	maxExpiry := after.Add(defaultPasswordResetTTL)
	if capturedExpiresAt.Before(minExpiry) || capturedExpiresAt.After(maxExpiry) {
		t.Errorf("expiresAt %v not in expected range [%v, %v]", capturedExpiresAt, minExpiry, maxExpiry)
	}
}

func TestRequestResetOIDCOnlyUserSkipsToken(t *testing.T) {
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if tokenCreated {
		t.Error("expected no token to be created for OIDC-only account")
	}
	if emailSent {
		t.Error("expected no email to be sent for OIDC-only account")
	}
}

func TestRequestResetRateLimited(t *testing.T) {
	rl := auth.NewRateLimiter(0, 1) // rate=0/sec, burst=1: first request passes, second is denied
	h := &PasswordResetHandler{
		Users:       &mockUserStore{},
		Resets:      &mockPasswordResetStore{},
		RateLimiter: rl,
	}
	postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`) // consumes the burst
	w := postJSON(t, h.RequestReset, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestResetPasswordExpiredTokenSentinel(t *testing.T) {
	// ErrExpiredToken from the store must be treated as a client error (400),
	// not an internal server error.
	resets := &mockPasswordResetStore{
		findFunc: func(_ context.Context, _ string) (*auth.PasswordResetToken, error) {
			return nil, auth.ErrExpiredToken
		},
	}
	h := newPasswordResetHandler(&mockUserStore{}, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"expiredtoken","newPassword":"newpassword123"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ErrExpiredToken, got %d", w.Code)
	}
}

func TestResetPasswordOIDCOnlyUser(t *testing.T) {
	// Attempting to reset the password of an OIDC-only account must be rejected.
	users := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: ""}, nil
		},
	}
	resets := validResetStore("u1")
	h := newPasswordResetHandler(users, resets)
	w := postJSON(t, h.ResetPassword, `{"token":"sometoken","newPassword":"newpassword123"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for OIDC-only account, got %d", w.Code)
	}
}
