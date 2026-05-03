package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"golang.org/x/crypto/bcrypt"
)

// DefaultRefreshTokenTTL is the default lifetime for refresh tokens when
// Sessions is configured on AuthHandler.
const DefaultRefreshTokenTTL = 7 * 24 * time.Hour

var dummyLoginBcryptHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("dummy-login-password"), auth.BcryptCost)
	if err != nil {
		panic(fmt.Errorf("generate dummy login bcrypt hash: %w", err))
	}
	return hash
}()

// AuthHandler holds dependencies for email/password auth endpoints.
type AuthHandler struct {
	Users    auth.UserStore
	JWT      *auth.JWTManager
	Sessions auth.SessionStore // optional; nil disables session tracking and refresh tokens
	// RefreshTokenTTL is the lifetime of refresh tokens. Defaults to
	// DefaultRefreshTokenTTL when Sessions is non-nil.
	RefreshTokenTTL time.Duration
	// RefreshCookieName is the name of the HttpOnly cookie used to store the
	// refresh token. When empty the refresh token is only returned in the
	// response body.
	RefreshCookieName   string
	CookieName          string
	SecureCookies       bool
	DisableSignup       bool
	RequireVerification bool
	Verifications       auth.EmailVerificationStore
}

type signupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type updateProfileRequest struct {
	Name string `json:"name"`
}

// AuthResponse is the JSON response for signup/login.
type AuthResponse struct {
	Token        string  `json:"token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	User         UserDTO `json:"user"`
}

// UserDTO is the public representation of a user.
type UserDTO struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	OIDCLinked    bool   `json:"oidc_linked"`
	IsAdmin       bool   `json:"is_admin"`
	EmailVerified bool   `json:"email_verified"`
}

// ToUserDTO converts an auth.User to a UserDTO.
func ToUserDTO(u *auth.User) UserDTO {
	return UserDTO{
		ID: u.ID, Name: u.Name, Email: u.Email,
		OIDCLinked: u.OIDCSubject != nil, IsAdmin: u.IsAdmin,
		EmailVerified: u.EmailVerified,
	}
}

// issueTokens delegates to the package-level issueTokens helper.
func (h *AuthHandler) issueTokens(w http.ResponseWriter, r *http.Request, userID string) (accessToken, refreshToken string, ok bool) {
	return issueTokens(w, r, userID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL)
}

// Signup creates a new user account.
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	if h.DisableSignup {
		writeError(r.Context(), w, http.StatusForbidden, "signup is disabled")
		return
	}

	var req signupRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if req.Name == "" || req.Email == "" || req.Password == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "name, email, and password are required")
		return
	}
	if !validatePassword(r.Context(), w, req.Password) {
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), auth.BcryptCost)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to hash password", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user, err := h.Users.CreateUser(r.Context(), req.Name, req.Email, string(hash))
	if err != nil {
		if errors.Is(err, auth.ErrEmailExists) {
			writeError(r.Context(), w, http.StatusConflict, "email already registered")
			return
		}
		slog.ErrorContext(r.Context(), "failed to create user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create user")
		return
	}

	token, refreshToken, ok := h.issueTokens(w, r, user.ID)
	if !ok {
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(r.Context(), w, http.StatusCreated, AuthResponse{Token: token, RefreshToken: refreshToken, User: ToUserDTO(user)})
}

// Login authenticates with email and password.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "email and password are required")
		return
	}

	user, err := h.Users.FindByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword(dummyLoginBcryptHash, []byte(req.Password))
			writeError(r.Context(), w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		slog.ErrorContext(r.Context(), "failed to find user by email", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}

	if user.PasswordHash == "" {
		_ = bcrypt.CompareHashAndPassword(dummyLoginBcryptHash, []byte(req.Password))
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if h.RequireVerification && !user.EmailVerified {
		writeError(r.Context(), w, http.StatusForbidden, "email address not verified")
		return
	}

	token, refreshToken, ok := h.issueTokens(w, r, user.ID)
	if !ok {
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(r.Context(), w, http.StatusOK, AuthResponse{Token: token, RefreshToken: refreshToken, User: ToUserDTO(user)})
}

// Logout clears the auth cookie. When Sessions is configured it also revokes
// the current session by parsing the session ID from the access token.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if h.Sessions != nil {
		if tok := auth.ExtractToken(r, h.CookieName); tok != "" {
			if claims, err := h.JWT.ParseTokenClaims(tok); err == nil && claims.ID != "" {
				if err := h.Sessions.DeleteSession(r.Context(), claims.ID, claims.UserID); err != nil && !errors.Is(err, auth.ErrNotFound) {
					slog.WarnContext(r.Context(), "failed to revoke session on logout",
						slog.String("session_id", claims.ID),
						slog.Any("error", err))
				}
			}
		}
		if h.RefreshCookieName != "" {
			ClearRefreshCookie(w, h.RefreshCookieName, h.SecureCookies)
		}
	}
	ClearAuthCookie(w, h.CookieName, h.SecureCookies)
	writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: "logged out"})
}

// RefreshToken exchanges a valid refresh token for a new access token and a
// new refresh token (rotation). The old session is revoked atomically.
// Sessions must be configured on AuthHandler; otherwise 404 is returned.
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if h.Sessions == nil {
		writeError(r.Context(), w, http.StatusNotFound, "refresh tokens not enabled")
		return
	}

	// Prefer the refresh cookie when configured, fall back to JSON body.
	rawRefresh := ""
	if h.RefreshCookieName != "" {
		if c, err := r.Cookie(h.RefreshCookieName); err == nil && c.Value != "" {
			rawRefresh = c.Value
		}
	}
	if rawRefresh == "" {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if !decodeJSON(r, w, &req) {
			return
		}
		rawRefresh = strings.TrimSpace(req.RefreshToken)
	}
	if rawRefresh == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "refresh token required")
		return
	}

	hash := auth.HashHighEntropyToken(rawRefresh)
	sess, err := h.Sessions.FindSessionByRefreshTokenHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) || errors.Is(err, auth.ErrSessionRevoked) {
			writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		slog.ErrorContext(r.Context(), "failed to find session by refresh token", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}
	if time.Now().After(sess.ExpiresAt) {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Revoke the consumed session before issuing a new one.
	if err := h.Sessions.DeleteSession(r.Context(), sess.ID, sess.UserID); err != nil {
		slog.ErrorContext(r.Context(), "failed to revoke old session on refresh", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}

	user, err := h.Users.FindByID(r.Context(), sess.UserID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusUnauthorized, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to find user on refresh", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}

	token, refreshToken, ok := h.issueTokens(w, r, user.ID)
	if !ok {
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(r.Context(), w, http.StatusOK, AuthResponse{Token: token, RefreshToken: refreshToken, User: ToUserDTO(user)})
}

// Me returns the current user's profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	user, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to get user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to get user")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, ToUserDTO(user))
}

// UpdateProfile updates the display name.
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	var req updateProfileRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "name is required")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	user, err := h.Users.UpdateName(r.Context(), userID, req.Name)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to update profile", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to update profile")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, ToUserDTO(user))
}

// ChangePassword changes the current user's password.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	if req.NewPassword == "" || req.CurrentPassword == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "current and new password required")
		return
	}
	if !validatePassword(r.Context(), w, req.NewPassword) {
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	user, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "failed to get user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to get user")
		return
	}
	if user.PasswordHash == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "cannot change password for OIDC-only account")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		writeError(r.Context(), w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), auth.BcryptCost)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if err := h.Users.UpdatePassword(r.Context(), userID, string(hash)); err != nil {
		slog.ErrorContext(r.Context(), "failed to update password", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to update password")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: "password updated"})
}
