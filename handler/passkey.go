package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnProvider abstracts the go-webauthn ceremony operations so they can be
// replaced with a test double. *webauthn.WebAuthn satisfies this interface.
type webAuthnProvider interface {
	BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishPasskeyLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, response *http.Request) (webauthn.User, *webauthn.Credential, error)
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error)
}

const passkeyChallengeExpiry = 5 * time.Minute

var (
	errPasskeySessionExpired = errors.New("passkey session expired")
	errListCredentials       = errors.New("failed to list credentials")
)

// PasskeyHandler holds dependencies for WebAuthn endpoints.
// URLParamFunc extracts URL parameters (router-agnostic).
type PasskeyHandler struct {
	Users         auth.UserStore
	Passkeys      auth.PasskeyStore
	WebAuthn      webAuthnProvider
	JWT           *auth.JWTManager
	CookieName    string
	SecureCookies bool
	Sessions      auth.SessionStore // optional; nil disables session tracking and refresh tokens
	// RefreshTokenTTL is the lifetime of refresh tokens. Defaults to
	// DefaultRefreshTokenTTL when Sessions is non-nil.
	RefreshTokenTTL time.Duration
	// RefreshCookieName is the name of the HttpOnly cookie used to store the
	// refresh token. Must be non-empty when Sessions is set; call Validate at
	// startup to catch this misconfiguration early.
	RefreshCookieName string
	URLParamFunc      func(r *http.Request, key string) string
}

// Validate checks that the handler is correctly configured and returns an error
// if any required fields are missing or incompatible. Call Validate once at
// server startup, after setting all optional fields, so that misconfiguration
// is caught immediately rather than at the first passkey ceremony completion.
func (h *PasskeyHandler) Validate() error {
	if h.Passkeys == nil {
		return errors.New("PasskeyHandler misconfigured: Passkeys is required")
	}
	if h.URLParamFunc == nil {
		return errors.New("PasskeyHandler misconfigured: URLParamFunc is required")
	}
	// Users and JWT are only required when WebAuthn is configured; without
	// WebAuthn the handler runs in a degraded mode where ceremony endpoints
	// return 503 and only ListCredentials/DeleteCredential remain available.
	if h.WebAuthn != nil {
		if h.Users == nil {
			return errors.New("PasskeyHandler misconfigured: Users is required when WebAuthn is configured")
		}
		if h.JWT == nil {
			return errors.New("PasskeyHandler misconfigured: JWT is required when WebAuthn is configured")
		}
	}
	if err := validateSessionConfig("PasskeyHandler", h.Sessions, h.RefreshCookieName); err != nil {
		return err
	}
	return nil
}

type passkeyUser struct {
	user        *auth.User
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *passkeyUser) WebAuthnName() string                       { return u.user.Email }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.user.Name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type passkeyChallengeData struct {
	SessionData webauthn.SessionData `json:"session_data"`
	Name        string               `json:"name,omitempty"`
}

type passkeyBeginResponse struct {
	SessionID string `json:"session_id"`
	Options   any    `json:"options"`
}

// passkeyEnabledBody is used instead of map[string]bool to avoid a map
// allocation on the passkey enabled response path.
type passkeyEnabledBody struct {
	Enabled bool `json:"enabled"`
}

// PasskeyCredentialDTO is the public representation of a passkey credential.
type PasskeyCredentialDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AAGUID    string    `json:"aaguid"`
	CreatedAt time.Time `json:"created_at"`
}

// ToPasskeyCredentialDTO converts an auth.PasskeyCredential to a PasskeyCredentialDTO.
func ToPasskeyCredentialDTO(c auth.PasskeyCredential) PasskeyCredentialDTO {
	return PasskeyCredentialDTO{ID: c.ID, Name: c.Name, AAGUID: c.AAGUID, CreatedAt: c.CreatedAt}
}

func loadWebAuthnCredentials(ctx context.Context, creds []auth.PasskeyCredential) []webauthn.Credential {
	result := make([]webauthn.Credential, 0, len(creds))
	for i := range creds {
		var waCred webauthn.Credential
		if err := json.Unmarshal([]byte(creds[i].CredentialData), &waCred); err != nil {
			slog.WarnContext(ctx, "skipping corrupted passkey credential", slog.String("id", creds[i].ID))
			continue
		}
		result = append(result, waCred)
	}
	return result
}

func (h *PasskeyHandler) storeChallenge(ctx context.Context, userID *string, sd *webauthn.SessionData, name string) (string, error) {
	enc, err := json.Marshal(passkeyChallengeData{SessionData: *sd, Name: name})
	if err != nil {
		return "", fmt.Errorf("marshal challenge: %w", err)
	}
	challenge, err := h.Passkeys.CreateChallenge(ctx, userID, string(enc), time.Now().UTC().Add(passkeyChallengeExpiry))
	if err != nil {
		return "", err
	}
	return challenge.ID, nil
}

func (h *PasskeyHandler) loadChallenge(ctx context.Context, id string) (*passkeyChallengeData, *string, error) {
	rec, err := h.Passkeys.GetAndDeleteChallenge(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if time.Now().UTC().After(rec.ExpiresAt) {
		return nil, nil, errPasskeySessionExpired
	}
	var data passkeyChallengeData
	if err = json.Unmarshal([]byte(rec.SessionData), &data); err != nil {
		return nil, nil, fmt.Errorf("unmarshal challenge: %w", err)
	}
	return &data, rec.UserID, nil
}

// Enabled reports whether passkeys are configured.
func (h *PasskeyHandler) Enabled(w http.ResponseWriter, r *http.Request) {
	writeJSON(r.Context(), w, http.StatusOK, passkeyEnabledBody{Enabled: h.WebAuthn != nil})
}

// BeginRegistration starts the WebAuthn registration ceremony.
func (h *PasskeyHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if h.WebAuthn == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "passkeys not configured")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeError(r.Context(), w, http.StatusBadRequest, "passkey name required (max 100 chars)")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	user, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to fetch user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to fetch user")
		return
	}
	existingCreds, err := h.Passkeys.ListCredentialsByUser(r.Context(), userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list credentials", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to list credentials")
		return
	}
	waCreds := loadWebAuthnCredentials(r.Context(), existingCreds)
	waUser := &passkeyUser{user: user, credentials: waCreds}

	options, sd, err := h.WebAuthn.BeginRegistration(waUser, webauthn.WithExclusions(webauthn.Credentials(waCreds).CredentialDescriptors()))
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to begin registration", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to begin registration")
		return
	}
	uid := userID
	sessionID, err := h.storeChallenge(r.Context(), &uid, sd, req.Name)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to store challenge", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to store challenge")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, passkeyBeginResponse{SessionID: sessionID, Options: options})
}

// FinishRegistration completes the WebAuthn registration ceremony.
func (h *PasskeyHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if h.WebAuthn == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "passkeys not configured")
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "session_id required")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	challengeData, storedUserID, err := h.loadChallenge(r.Context(), sessionID)
	if err != nil {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid or expired session")
		return
	}
	if storedUserID != nil && *storedUserID != userID {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid session")
		return
	}

	user, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to fetch user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to fetch user")
		return
	}
	existingCreds, err := h.Passkeys.ListCredentialsByUser(r.Context(), userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list credentials", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to list credentials")
		return
	}
	waUser := &passkeyUser{user: user, credentials: loadWebAuthnCredentials(r.Context(), existingCreds)}

	credential, err := h.WebAuthn.FinishRegistration(waUser, challengeData.SessionData, r)
	if err != nil {
		slog.WarnContext(r.Context(), "webauthn finish registration failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusBadRequest, "registration verification failed")
		return
	}

	credData, err := json.Marshal(credential)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to marshal credential", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to marshal credential")
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(credential.ID)
	aaguid := base64.RawURLEncoding.EncodeToString(credential.Authenticator.AAGUID)

	stored, err := h.Passkeys.CreateCredential(r.Context(), userID, challengeData.Name, credID, string(credData), aaguid)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to store credential", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to store credential")
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, ToPasskeyCredentialDTO(*stored))
}

// BeginAuthentication starts the passkey login ceremony.
func (h *PasskeyHandler) BeginAuthentication(w http.ResponseWriter, r *http.Request) {
	if h.WebAuthn == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "passkeys not configured")
		return
	}
	options, sd, err := h.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to begin login", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to begin login")
		return
	}
	sessionID, err := h.storeChallenge(r.Context(), nil, sd, "")
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to store challenge", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to store challenge")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, passkeyBeginResponse{SessionID: sessionID, Options: options})
}

// FinishAuthentication completes the passkey login ceremony.
func (h *PasskeyHandler) FinishAuthentication(w http.ResponseWriter, r *http.Request) {
	if h.WebAuthn == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "passkeys not configured")
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "session_id required")
		return
	}
	challengeData, _, err := h.loadChallenge(r.Context(), sessionID)
	if err != nil {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired session")
		return
	}

	var authedUserID, authedCredentialID string
	var authedUser *auth.User
	var listCredsErr error
	var userLookupErr error

	handler := webauthn.DiscoverableUserHandler(func(rawID, userHandle []byte) (webauthn.User, error) {
		credID := base64.RawURLEncoding.EncodeToString(rawID)
		cred, err := h.Passkeys.FindCredentialByCredentialID(r.Context(), credID)
		if err != nil {
			return nil, fmt.Errorf("credential not found: %w", err)
		}
		user, err := h.Users.FindByID(r.Context(), cred.UserID)
		if err != nil {
			userLookupErr = err
			return nil, fmt.Errorf("user not found: %w", err)
		}
		userCreds, err := h.Passkeys.ListCredentialsByUser(r.Context(), user.ID)
		if err != nil {
			listCredsErr = err
			return nil, fmt.Errorf("%w: %w", errListCredentials, err)
		}
		authedUserID = user.ID
		authedCredentialID = credID
		authedUser = user
		return &passkeyUser{user: user, credentials: loadWebAuthnCredentials(r.Context(), userCreds)}, nil
	})

	_, updatedCred, err := h.WebAuthn.FinishPasskeyLogin(handler, challengeData.SessionData, r)
	if err != nil {
		if listCredsErr != nil {
			slog.ErrorContext(r.Context(), "failed to list credentials", slog.Any("error", listCredsErr))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to list credentials")
		} else if errors.Is(userLookupErr, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
		} else if userLookupErr != nil {
			slog.ErrorContext(r.Context(), "failed to fetch user", slog.Any("error", userLookupErr))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to fetch user")
		} else {
			writeError(r.Context(), w, http.StatusUnauthorized, "authentication failed")
		}
		return
	}

	if data, err := json.Marshal(updatedCred); err != nil {
		slog.WarnContext(r.Context(), "failed to marshal credential for counter update",
			slog.String("user_id", authedUserID),
			slog.String("credential_id", authedCredentialID),
			slog.Any("error", err))
	} else if err := h.Passkeys.UpdateCredentialData(r.Context(), authedUserID, authedCredentialID, string(data)); err != nil {
		slog.WarnContext(r.Context(), "failed to update credential counter",
			slog.String("user_id", authedUserID),
			slog.String("credential_id", authedCredentialID),
			slog.Any("error", err))
	}

	token, refreshToken, ok := issueTokens(w, r, authedUserID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL)
	if !ok {
		return
	}

	setNoCacheHeaders(w)
	writeJSON(r.Context(), w, http.StatusOK, AuthResponse{Token: token, RefreshToken: refreshToken, User: ToUserDTO(authedUser)})
}

// ListCredentials returns all passkey credentials for the current user.
func (h *PasskeyHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	creds, err := h.Passkeys.ListCredentialsByUser(r.Context(), userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list credentials", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to list credentials")
		return
	}
	dtos := make([]PasskeyCredentialDTO, len(creds))
	for i := range creds {
		dtos[i] = ToPasskeyCredentialDTO(creds[i])
	}
	writeJSON(r.Context(), w, http.StatusOK, dtos)
}

// DeleteCredential removes a passkey credential.
func (h *PasskeyHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	credID := h.URLParamFunc(r, "id")
	if credID == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid credential ID")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	if err := h.Passkeys.DeleteCredential(r.Context(), credID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "credential not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to delete credential", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to delete credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
