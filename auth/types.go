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
	ErrInvalidToken    = errors.New("invalid token")
	ErrExpiredToken    = errors.New("token expired")
	ErrEmailExists     = errors.New("email already exists")
	ErrTOTPNotFound    = errors.New("totp not configured")
	ErrInvalidTOTPCode = errors.New("invalid TOTP code")
)

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
	// Returns ErrTOTPNotFound (or sql.ErrNoRows) when none exists.
	GetTOTPSecret(ctx context.Context, userID string) (*TOTPSecret, error)
	// DeleteTOTPSecret removes the TOTP secret for a user.
	DeleteTOTPSecret(ctx context.Context, userID string) error
}
