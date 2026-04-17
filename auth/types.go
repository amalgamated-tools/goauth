// Package auth provides JWT management, authentication middleware, API key
// support, rate limiting, and cryptographic utilities for Go web applications.
//
// It defines store interfaces that consuming applications implement with their
// own database layer. The package is router-agnostic — handlers use standard
// net/http types.
package auth

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors.
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token expired")
	ErrEmailExists      = errors.New("email already exists")
	ErrEmailNotVerified = errors.New("email not verified")
	ErrSessionRevoked   = errors.New("session revoked")
	// ErrNotFound is returned by store methods when the requested record does
	// not exist. Implementations must return this (or wrap it) instead of
	// driver-specific errors such as sql.ErrNoRows.
	ErrNotFound        = errors.New("not found")
	ErrTOTPNotFound    = errors.New("totp not configured")
	ErrInvalidTOTPCode = errors.New("invalid TOTP code")
)

// PasswordResetToken represents a pending email-based password reset request.
type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// User represents an authenticated user. Consuming applications may embed
// this in a larger struct to add app-specific fields.
type User struct {
	ID            string
	Name          string
	Email         string
	PasswordHash  string
	OIDCSubject   *string
	IsAdmin       bool
	EmailVerified bool
	CreatedAt     time.Time
}

// EmailVerificationToken represents an email address verification request.
type EmailVerificationToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// APIKey represents a long-lived authentication token.
type APIKey struct {
	ID         string
	UserID     string
	Name       string
	KeyHash    string
	KeyPrefix  string
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// PasskeyCredential represents a stored WebAuthn credential.
type PasskeyCredential struct {
	ID             string
	UserID         string
	Name           string
	CredentialID   string
	CredentialData string
	AAGUID         string
	CreatedAt      time.Time
}

// PasskeyChallenge represents an ephemeral WebAuthn challenge.
type PasskeyChallenge struct {
	ID          string
	UserID      *string
	SessionData string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// UserStore defines data access for user operations.
type UserStore interface {
	CreateUser(ctx context.Context, name, email, passwordHash string) (*User, error)
	CreateOIDCUser(ctx context.Context, name, email, oidcSubject string) (*User, error)
	// FindByEmail returns ErrNotFound when no user matches the given email.
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id string) (*User, error)
	FindByOIDCSubject(ctx context.Context, subject string) (*User, error)
	LinkOIDCSubject(ctx context.Context, userID, oidcSubject string) error
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	UpdateName(ctx context.Context, userID, name string) (*User, error)
	IsAdmin(ctx context.Context, userID string) (bool, error)
	CountUsers(ctx context.Context) (int, error)
}

// APIKeyStore defines data access for API key operations.
type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, userID, name, keyHash, keyPrefix string) (*APIKey, error)
	ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error)
	FindAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*APIKey, error)
	ValidateAPIKey(ctx context.Context, keyHash string) (userID string, apiKeyID string, err error)
	TouchAPIKeyLastUsed(ctx context.Context, id string) error
	DeleteAPIKey(ctx context.Context, id, userID string) error
}

// Session represents an active user session. Each session is bound to a
// single refresh token hash, enabling server-side revocation.
type Session struct {
	ID               string
	UserID           string
	RefreshTokenHash string
	UserAgent        string
	IPAddress        string
	ExpiresAt        time.Time
	CreatedAt        time.Time
}

// SessionStore defines data access for session operations.
type SessionStore interface {
	// CreateSession persists a new session and returns it.
	CreateSession(ctx context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*Session, error)
	// FindSessionByID returns a session by its ID. Returns sql.ErrNoRows when not found.
	FindSessionByID(ctx context.Context, id string) (*Session, error)
	// FindSessionByRefreshTokenHash returns a session by its refresh token hash. Returns sql.ErrNoRows when not found.
	FindSessionByRefreshTokenHash(ctx context.Context, refreshTokenHash string) (*Session, error)
	// ListSessionsByUser returns all sessions belonging to a user.
	ListSessionsByUser(ctx context.Context, userID string) ([]Session, error)
	// DeleteSession removes a session by ID, scoped to a user. Returns sql.ErrNoRows when not found.
	DeleteSession(ctx context.Context, id, userID string) error
	// DeleteAllSessionsByUser removes all sessions for a user.
	DeleteAllSessionsByUser(ctx context.Context, userID string) error
	// DeleteExpiredSessions removes sessions past their expiry time.
	DeleteExpiredSessions(ctx context.Context) error
}

// PasskeyStore defines data access for WebAuthn operations.
type PasskeyStore interface {
	CreateChallenge(ctx context.Context, userID *string, sessionData string, expiresAt time.Time) (*PasskeyChallenge, error)
	GetAndDeleteChallenge(ctx context.Context, id string) (*PasskeyChallenge, error)
	DeleteExpiredChallenges(ctx context.Context) error
	CreateCredential(ctx context.Context, userID, name, credentialID, credentialData, aaguid string) (*PasskeyCredential, error)
	ListCredentialsByUser(ctx context.Context, userID string) ([]PasskeyCredential, error)
	FindCredentialByCredentialID(ctx context.Context, credentialID string) (*PasskeyCredential, error)
	FindCredentialByIDAndUser(ctx context.Context, id, userID string) (*PasskeyCredential, error)
	UpdateCredentialData(ctx context.Context, userID, credentialID, credentialData string) error
	DeleteCredential(ctx context.Context, id, userID string) error
}

// EmailVerificationStore defines data access for email verification tokens.
type EmailVerificationStore interface {
	// CreateEmailVerification stores a new hashed token for the given user.
	CreateEmailVerification(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error)
	// ConsumeEmailVerification looks up the token by its hash, deletes it, and
	// returns it. Returns sql.ErrNoRows when not found.
	ConsumeEmailVerification(ctx context.Context, tokenHash string) (*EmailVerificationToken, error)
	// SetEmailVerified marks the user's email address as verified.
	SetEmailVerified(ctx context.Context, userID string) error
}

// TOTPSecret represents a stored TOTP secret for a user.
type TOTPSecret struct {
	ID        string
	UserID    string
	Secret    string // base32-encoded secret; applications may store it encrypted
	CreatedAt time.Time
}

// TOTPStore defines data access for TOTP secrets.
type TOTPStore interface {
	// CreateTOTPSecret persists a new TOTP secret for a user, replacing any
	// existing one.
	CreateTOTPSecret(ctx context.Context, userID, secret string) (*TOTPSecret, error)
	// GetTOTPSecret retrieves the active TOTP secret for a user.
	// Returns ErrTOTPNotFound when none exists.
	GetTOTPSecret(ctx context.Context, userID string) (*TOTPSecret, error)
	// DeleteTOTPSecret removes the TOTP secret for a user.
	DeleteTOTPSecret(ctx context.Context, userID string) error
}

// PasswordResetStore defines data access for email-based password reset token operations.
type PasswordResetStore interface {
	// CreatePasswordResetToken stores a hashed reset token for userID, expiring at expiresAt.
	CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
	// FindPasswordResetToken retrieves a token record by its hash.
	// Returns ErrInvalidToken if no matching record exists.
	FindPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	// DeletePasswordResetToken removes a token record by ID, consuming it after use.
	DeletePasswordResetToken(ctx context.Context, id string) error
	// DeleteExpiredPasswordResetTokens removes all expired token records.
	// Callers are responsible for scheduling periodic invocations (e.g. a
	// background goroutine or cron job) to prevent unbounded token accumulation.
	DeleteExpiredPasswordResetTokens(ctx context.Context) error
}
