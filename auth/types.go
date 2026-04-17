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
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
	ErrEmailExists  = errors.New("email already exists")
	// ErrNotFound is returned by store methods when the requested record does
	// not exist. Implementations must return this (or wrap it) instead of
	// driver-specific errors such as sql.ErrNoRows.
	ErrNotFound = errors.New("not found")
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
	ID           string
	Name         string
	Email        string
	PasswordHash string
	OIDCSubject  *string
	IsAdmin      bool
	CreatedAt    time.Time
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
}
