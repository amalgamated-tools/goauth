package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/amalgamated-tools/goauth/auth"
	"golang.org/x/crypto/bcrypt"
)

var dummyLoginBcryptHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("dummy-login-password"), auth.BcryptCost)
	if err != nil {
		panic(fmt.Errorf("generate dummy login bcrypt hash: %w", err))
	}
	return hash
}()

// AuthHandler holds dependencies for email/password auth endpoints.
type AuthHandler struct {
	Users                auth.UserStore
	JWT                  *auth.JWTManager
	CookieName           string
	SecureCookies        bool
	DisableSignup        bool
	RequireVerification  bool
	Verifications        auth.EmailVerificationStore
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
	Token string  `json:"token"`
	User  UserDTO `json:"user"`
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

	token, err := h.JWT.CreateToken(r.Context(), user.ID)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
		return
	}

	SetAuthCookie(w, token, h.CookieName, h.SecureCookies)
	writeJSON(r.Context(), w, http.StatusCreated, AuthResponse{Token: token, User: ToUserDTO(user)})
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
		if errors.Is(err, sql.ErrNoRows) {
			_ = bcrypt.CompareHashAndPassword(dummyLoginBcryptHash, []byte(req.Password))
			writeError(r.Context(), w, http.StatusUnauthorized, "invalid email or password")
			return
		}
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

	token, err := h.JWT.CreateToken(r.Context(), user.ID)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
		return
	}

	SetAuthCookie(w, token, h.CookieName, h.SecureCookies)
	writeJSON(r.Context(), w, http.StatusOK, AuthResponse{Token: token, User: ToUserDTO(user)})
}

// Logout clears the auth cookie.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ClearAuthCookie(w, h.CookieName, h.SecureCookies)
	writeJSON(r.Context(), w, http.StatusOK, map[string]string{"message": "logged out"})
}

// Me returns the current user's profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	user, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
			return
		}
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
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to update password")
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]string{"message": "password updated"})
}
