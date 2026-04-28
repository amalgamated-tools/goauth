package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockEmailVerificationStore
// ---------------------------------------------------------------------------

type mockEmailVerificationStore struct {
	createFunc  func(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.EmailVerificationToken, error)
	consumeFunc func(ctx context.Context, tokenHash string) (*auth.EmailVerificationToken, error)
	setVerified func(ctx context.Context, userID string) error
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
		SendEmail:     func(_ context.Context, _, _ string) error { return nil },
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

func TestSendVerification_success(t *testing.T) {
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
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "alice@test.com", sentTo)
	require.NotEmpty(t, sentToken)
}

func TestSendVerification_alreadyVerified(t *testing.T) {
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
	require.Equal(t, http.StatusOK, w.Code)
	require.False(t, emailSent)
}

func TestSendVerification_userNotFound(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
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
	require.Equal(t, http.StatusOK, w.Code)
	require.False(t, emailSent)
}

func TestSendVerification_missingEmail(t *testing.T) {
	h := newEmailVerificationHandler(&mockUserStore{}, &mockEmailVerificationStore{})
	w := postJSON(t, h.SendVerification, `{"email":""}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSendVerification_invalidJSON(t *testing.T) {
	h := newEmailVerificationHandler(&mockUserStore{}, &mockEmailVerificationStore{})
	w := postJSON(t, h.SendVerification, "not-json")
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSendVerification_storeError(t *testing.T) {
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
	h := newEmailVerificationHandler(store, verStore)
	w := postJSON(t, h.SendVerification, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestSendVerification_userStoreError(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	// Non-auth.ErrNotFound errors log and return 200 to avoid leaking info.
	h := newEmailVerificationHandler(store, &mockEmailVerificationStore{})
	w := postJSON(t, h.SendVerification, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestSendVerification_noSendEmailFunc(t *testing.T) {
	createCalled := false
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", EmailVerified: false}, nil
		},
	}
	verStore := &mockEmailVerificationStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.EmailVerificationToken, error) {
			createCalled = true
			return &auth.EmailVerificationToken{}, nil
		},
	}
	// SendEmail is nil — must return 503 and must not write to the DB.
	h := newEmailVerificationHandler(store, verStore)
	h.SendEmail = nil
	w := postJSON(t, h.SendVerification, `{"email":"alice@test.com"}`)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.False(t, createCalled, "CreateEmailVerification must not be called when SendEmail is nil")
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

func TestVerifyEmail_success(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, hash string) (*auth.EmailVerificationToken, error) {
			if hash != tokenHashFor(validToken) {
				return nil, auth.ErrNotFound
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

	require.Equal(t, http.StatusOK, w.Code)
}

func TestVerifyEmail_missingToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/verify-email", nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, &mockEmailVerificationStore{}).VerifyEmail(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyEmail_invalidToken(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, _ string) (*auth.EmailVerificationToken, error) {
			return nil, auth.ErrNotFound
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token=badtoken", nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyEmail_expiredToken(t *testing.T) {
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

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyEmail_consumeStoreError(t *testing.T) {
	verStore := &mockEmailVerificationStore{
		consumeFunc: func(_ context.Context, _ string) (*auth.EmailVerificationToken, error) {
			return nil, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+validToken, nil)
	w := httptest.NewRecorder()
	newEmailVerificationHandler(&mockUserStore{}, verStore).VerifyEmail(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestVerifyEmail_setVerifiedStoreError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Login with RequireVerification
// ---------------------------------------------------------------------------

func TestLogin_blockedWhenUnverified(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash, EmailVerified: false}, nil
		},
	}
	h := newAuthHandler(store)
	h.RequireVerification = true

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestLogin_allowedWhenVerified(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash, EmailVerified: true}, nil
		},
	}
	h := newAuthHandler(store)
	h.RequireVerification = true

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestLogin_verificationNotRequired(t *testing.T) {
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
	require.Equal(t, http.StatusOK, w.Code)
}

func TestUserDTO_emailVerifiedField(t *testing.T) {
	u := &auth.User{ID: "u1", Name: "Alice", Email: "a@b.com", EmailVerified: true}
	dto := ToUserDTO(u)
	require.True(t, dto.EmailVerified)

	u2 := &auth.User{ID: "u2", Name: "Bob", Email: "b@c.com", EmailVerified: false}
	dto2 := ToUserDTO(u2)
	require.False(t, dto2.EmailVerified)
}
