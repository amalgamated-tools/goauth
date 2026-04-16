package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

func newTestOIDCHandler() *OIDCHandler {
	return &OIDCHandler{
		Users:         &mockUserStore{},
		JWT:           newTestJWT(),
		CookieName:    "auth",
		SecureCookies: false,
		linkNonces:    make(map[string]linkNonce),
	}
}

// ---------------------------------------------------------------------------
// signLinkState / parseLinkState
// ---------------------------------------------------------------------------

func TestSignAndParseLinkState(t *testing.T) {
	h := newTestOIDCHandler()

	randomState := "somerandomstate1234"
	userID := "user-abc"

	signed := h.signLinkState(randomState, userID)
	if signed == "" {
		t.Fatal("expected non-empty signed state")
	}

	parsed := h.parseLinkState(signed)
	if parsed != userID {
		t.Errorf("expected %q, got %q", userID, parsed)
	}
}

func TestParseLinkStateInvalidFormat(t *testing.T) {
	h := newTestOIDCHandler()

	// Not enough parts.
	for _, bad := range []string{
		"",
		"only-one-part",
		"two.parts",
	} {
		if got := h.parseLinkState(bad); got != "" {
			t.Errorf("input %q: expected empty, got %q", bad, got)
		}
	}
}

func TestParseLinkStateTamperedSignature(t *testing.T) {
	h := newTestOIDCHandler()

	signed := h.signLinkState("randomstate", "user-1")
	// Corrupt the last character of the signature (third dot-separated part).
	tampered := signed[:len(signed)-1] + "X"
	if got := h.parseLinkState(tampered); got != "" {
		t.Errorf("tampered signature should not parse, got %q", got)
	}
}

func TestParseLinkStateWrongKey(t *testing.T) {
	h1 := newTestOIDCHandler()
	h2 := &OIDCHandler{
		JWT:        newTestJWT(), // same secret, different derived key...
		linkNonces: make(map[string]linkNonce),
	}
	// Give h2 a different JWT manager (different secret).
	mgr2, _ := auth.NewJWTManager("different-secret-32bytes-here!!!!", time.Hour, "test")
	h2.JWT = mgr2

	signed := h1.signLinkState("state123", "user-xyz")
	if got := h2.parseLinkState(signed); got != "" {
		t.Errorf("signed by h1 should not verify with h2's key, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// consumeLinkNonce / CreateLinkNonce
// ---------------------------------------------------------------------------

func TestConsumeLinkNonce(t *testing.T) {
	h := newTestOIDCHandler()

	nonce := "test-nonce-123"
	h.linkNonces[nonce] = linkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(time.Minute)}

	got := h.consumeLinkNonce(nonce)
	if got != "user-1" {
		t.Errorf("expected user-1, got %q", got)
	}

	// Second consumption of the same nonce should return empty.
	if got2 := h.consumeLinkNonce(nonce); got2 != "" {
		t.Errorf("nonce should be consumed, got %q", got2)
	}
}

func TestConsumeLinkNonceExpired(t *testing.T) {
	h := newTestOIDCHandler()

	nonce := "expired-nonce"
	h.linkNonces[nonce] = linkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(-time.Second)}

	if got := h.consumeLinkNonce(nonce); got != "" {
		t.Errorf("expired nonce should return empty, got %q", got)
	}
}

func TestConsumeLinkNonceNotFound(t *testing.T) {
	h := newTestOIDCHandler()
	if got := h.consumeLinkNonce("does-not-exist"); got != "" {
		t.Errorf("unknown nonce should return empty, got %q", got)
	}
}

func TestCreateLinkNonce(t *testing.T) {
	h := newTestOIDCHandler()

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-42")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	nonce := resp["nonce"]
	if nonce == "" {
		t.Fatal("expected non-empty nonce")
	}

	// The nonce should be consumable.
	got := h.consumeLinkNonce(nonce)
	if got != "user-42" {
		t.Errorf("expected user-42, got %q", got)
	}
}

func TestCreateLinkNonceCleansUpExpiredEntries(t *testing.T) {
	h := newTestOIDCHandler()

	// Pre-populate with an expired entry.
	h.linkNonces["old-nonce"] = linkNonce{UserID: "old-user", ExpiresAt: time.Now().Add(-time.Minute)}

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-42")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	h.linkNoncesMu.Lock()
	_, exists := h.linkNonces["old-nonce"]
	h.linkNoncesMu.Unlock()
	if exists {
		t.Error("expected expired nonce to be cleaned up")
	}
}

// ---------------------------------------------------------------------------
// findOrCreateUser
// ---------------------------------------------------------------------------

func TestFindOrCreateUserByOIDCSubject(t *testing.T) {
	existing := &auth.User{ID: "u1", Email: "a@b.com"}
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub1", "a@b.com", "Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "u1" {
		t.Errorf("expected u1, got %q", user.ID)
	}
}

func TestFindOrCreateUserByEmail(t *testing.T) {
	existing := &auth.User{ID: "u2", Email: "b@c.com"}
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, sql.ErrNoRows
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub2", "b@c.com", "Bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "u2" {
		t.Errorf("expected u2, got %q", user.ID)
	}
}

func TestFindOrCreateUserCreatesNew(t *testing.T) {
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, sql.ErrNoRows
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, sql.ErrNoRows
		},
		createOIDCUserFunc: func(_ context.Context, name, email, sub string) (*auth.User, error) {
			return &auth.User{ID: "new-u", Name: name, Email: email}, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub-new", "new@example.com", "New User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "new-u" {
		t.Errorf("expected new-u, got %q", user.ID)
	}
}

// ---------------------------------------------------------------------------
// handleLinkCallback
// ---------------------------------------------------------------------------

func TestHandleLinkCallbackSuccess(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: nil}, nil
		},
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, sql.ErrNoRows
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "user-1", "oidc-sub")

	if w.Code != http.StatusFound {
		t.Errorf("expected redirect 302, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/?oidc_linked=true" {
		t.Errorf("expected redirect to /?oidc_linked=true, got %q", loc)
	}
}

func TestHandleLinkCallbackUserNotFound(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, sql.ErrNoRows
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "missing-user", "oidc-sub")

	if w.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "/?oidc_linked=true" {
		t.Error("expected error redirect, not success")
	}
}

func TestHandleLinkCallbackAlreadyLinked(t *testing.T) {
	sub := "existing-sub"
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: &sub}, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "user-1", "other-sub")

	if w.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "/?oidc_linked=true" {
		t.Error("expected error redirect for already-linked account")
	}
}
