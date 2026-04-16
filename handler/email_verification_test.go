package handler

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

// ---------------------------------------------------------------------------
// mockEmailVerificationStore
// ---------------------------------------------------------------------------

type mockEmailVerificationStore struct {
	createFunc   func(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.EmailVerificationToken, error)
	consumeFunc  func(ctx context.Context, tokenHash string) (*auth.EmailVerificationToken, error)
	setVerified  func(ctx context.Context, userID string) error
}

func (m *mockEmailVerificationStore) CreateEmailVerification(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.EmailVerificationToken, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, tokenHash, expiresAt)
	}
	return &auth.EmailVerificationToken{ID: "tok-id", UserID: userID, TokenHash: tokenHash, ExpiresAt: expiresAt}, nil
}

func (m *mockEmailVerificationStore) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*auth.EmailVerificationToken, error) {
	if m.consumeFunc != nil {
		return m.consumeFunc(ctx, tokenHash)
	}
	return &auth.EmailVerificationToken{ID: "tok-id", UserID: "u1", TokenHash: tokenHash, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (m *mockEmailVerificationStore) SetEmailVerified(ctx context.Context, userID string) error {
	if m.setVerified != nil {
		return m.setVerified(ctx, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newEmailVerificationHandler(users auth.UserStore, store auth.EmailVerificationStore) *EmailVerificationHandler {
	return &EmailVerificationHandler{
		Users:         users,
		Verifications: store,
	}
}

// validToken is a 64-hex-char plaintext token (32 bytes).
const validToken = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

// tokenHashFor returns the hash that the handler would store for the given plaintext.
func tokenHashFor(plaintext string) string {
	return auth.HashHighEntropyToken(plaintext)
}

// ---------------------------------------------------------------------------
// SendVerification
// ---------------------------------------------------------------------------

func TestSendVerificationSuccess(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", EmailVerified: false}, nil
		},
	}
	var sentTo, sentToken string
	h := newEmailVerificationHandler(store, &mockEmailVerificationStore{})
	h.SendEmail = func(_ context.Context, to, token string) error {
		sentTo = to
		sentToken = token
		return nil
	}

	w := postJSON(t, h.SendVerification, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if sentTo != "alice@test.com" {
		t.Errorf("expected email sent to alice@test.com, got %q", sentTo)
	}
	if sentToken == "" {
		t.Error("expected non-empty token to be passed to SendEmail")
	}
}

func TestSendVerificationAlreadyVerified(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", EmailVerified: true}, nil
		},
	}
	emailSent := false
	h := newEmailVerificationHandler(store, &mockEmailVerificationStore{})
	h.SendEmail = func(_ context.Context, _, _ string) error {
		emailSent = true
		return nil
	}

	w := postJSON(t, h.SendVerification, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if emailSent {
		t.Error("expected no email sent for already-verified user")
	}
}

func TestSendVerificationUserNotFound(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, sql.ErrNoRows
		},
	}
	emailSent := false
	h := newEmailVerificationHandler(store, &mockEmailVerificationStore{})
	h.SendEmail = func(_ context.Context, _, _ string) error {
		emailSent = true
		return nil
	}

	// Should still return 200 to avoid leaking account existence.
	w := postJSON(t, h.SendVerification, `{"email":"nobody@test.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if emailSent {
		t.Error("expected no email sent when user not found")
	}
}

func TestSendVerificationMissingEmail(t *testing.T) {
	h := newEmailVerificationHandler(&mockUserStore{}, &mockEmailVerificationStore{})
	w := postJSON(t, h.SendVerification, `{"email":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSendVerificationInvalidJSON(t *testing.T) {
	h := newEmailVerificationHandler(&mockUserStore{}, &mockEmailVerificationStore{})
	w := postJSON(t, h.SendVerification, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSendVerificationStoreError(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", EmailVerified: false}, nil
		},
	}
	verStore := &mockEmailVerificationStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.EmailVerificationToken, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newEmailVerificationHandler(store, verStore).SendVerification, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestSendVerificationUserStoreError(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	// Non-sql.ErrNoRows errors log and return 200 to avoid leaking info.
	w := postJSON(t, newEmailVerificationHandler(store, &mockEmailVerificationStore{}).SendVerification, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSendVerificationNoSendEmailFunc(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", EmailVerified: false}, nil
		},
	}
	// SendEmail is nil — token still created, no panic.
	h := newEmailVerificationHandler(store, &mockEmailVerificationStore{})
	w := postJSON(t, h.SendVerification, `{"email":"alice@test.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

func TestVerifyEmailSuccess(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, hash string) (*auth.EmailVerificationToken, error) {
			if hash != tokenHashFor(validToken) {
				return nil, sql.ErrNoRows
			}
			return &auth.EmailVerificationToken{
				ID: "tok-id", UserID: "u1",
				TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+validToken, nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmailMissingToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/verify-email", nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, &mockEmailVerificationStore{}).VerifyEmail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestVerifyEmailInvalidToken(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, _ string) (*auth.EmailVerificationToken, error) {
			return nil, sql.ErrNoRows
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token=badtoken", nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestVerifyEmailExpiredToken(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, hash string) (*auth.EmailVerificationToken, error) {
			return &auth.EmailVerificationToken{
				ID: "tok-id", UserID: "u1",
				TokenHash: hash, ExpiresAt: time.Now().Add(-time.Hour), // expired
			}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+validToken, nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired token, got %d", w.Code)
	}
}

func TestVerifyEmailConsumeStoreError(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, _ string) (*auth.EmailVerificationToken, error) {
			return nil, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+validToken, nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestVerifyEmailSetVerifiedStoreError(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, hash string) (*auth.EmailVerificationToken, error) {
			return &auth.EmailVerificationToken{
				ID: "tok-id", UserID: "u1",
				TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		setVerified: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+validToken, nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Login with RequireVerification
// ---------------------------------------------------------------------------

func TestLoginBlockedWhenUnverified(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash, EmailVerified: false}, nil
		},
	}
	h := newAuthHandler(store)
	h.RequireVerification = true

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unverified user, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestLoginAllowedWhenVerified(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash, EmailVerified: true}, nil
		},
	}
	h := newAuthHandler(store)
	h.RequireVerification = true

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for verified user, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestLoginVerificationNotRequired(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			// EmailVerified is false but RequireVerification is false.
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash, EmailVerified: false}, nil
		},
	}
	h := newAuthHandler(store)
	// RequireVerification defaults to false.

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when RequireVerification=false, got %d", w.Code)
	}
}

func TestUserDTOEmailVerifiedField(t *testing.T) {
	u := &auth.User{ID: "u1", Name: "Alice", Email: "a@b.com", EmailVerified: true}
	dto := ToUserDTO(u)
	if !dto.EmailVerified {
		t.Error("expected EmailVerified=true in UserDTO")
	}

	u2 := &auth.User{ID: "u2", Name: "Bob", Email: "b@c.com", EmailVerified: false}
	dto2 := ToUserDTO(u2)
	if dto2.EmailVerified {
		t.Error("expected EmailVerified=false in UserDTO")
	}
}
