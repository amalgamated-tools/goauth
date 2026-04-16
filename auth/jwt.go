package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/hkdf"
)

// Claims represents the JWT payload.
type Claims struct {
	UserID string `json:"sub"`
	jwt.RegisteredClaims
}

// JWTManager handles token creation and validation.
type JWTManager struct {
	secret  []byte
	oidcKey []byte
	issuer  string
	ttl     time.Duration
}

// MinSecretLength is the minimum recommended length for a JWT signing secret.
const MinSecretLength = 32

// NewJWTManager creates a new JWTManager. If secret is empty, a random one
// is generated (tokens won't survive restarts). Issuer is used for iss/aud claims.
func NewJWTManager(secret string, ttl time.Duration, issuer string) (*JWTManager, error) {
	key := []byte(secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate random JWT secret: %w", err)
		}
	}
	oidcKey := make([]byte, 32)
	r := hkdf.New(sha256.New, key, nil, []byte("oidc-link-state"))
	if _, err := r.Read(oidcKey); err != nil {
		return nil, fmt.Errorf("derive OIDC HMAC key: %w", err)
	}

	if issuer == "" {
		issuer = "goauth"
	}

	return &JWTManager{secret: key, oidcKey: oidcKey, issuer: issuer, ttl: ttl}, nil
}

// CreateToken generates a signed JWT for the given user ID.
func (j *JWTManager) CreateToken(ctx context.Context, userID string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.issuer},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

// CreateTokenWithSession generates a signed JWT for the given user ID and
// session ID. The session ID is embedded as the jti claim, enabling the
// middleware to verify session liveness when a SessionStore is configured.
func (j *JWTManager) CreateTokenWithSession(ctx context.Context, userID, sessionID string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.issuer},
			Subject:   userID,
			ID:        sessionID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

// ValidateToken parses and validates a JWT, returning the claims if valid.
func (j *JWTManager) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	},
		jwt.WithIssuer(j.issuer),
		jwt.WithAudience(j.issuer),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// NewSecretEncrypter returns a SecretEncrypter derived from the JWT secret.
func (j *JWTManager) NewSecretEncrypter() (*SecretEncrypter, error) {
	return newSecretEncrypter(j.secret)
}

// HMACSign produces an HMAC-SHA256 signature using the OIDC-derived sub-key.
func (j *JWTManager) HMACSign(data []byte) []byte {
	mac := hmac.New(sha256.New, j.oidcKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// HMACVerify checks that sig is a valid HMAC-SHA256 of data.
func (j *JWTManager) HMACVerify(data, sig []byte) bool {
	return hmac.Equal(j.HMACSign(data), sig)
}

// ParseTokenClaims parses a JWT and returns the claims, validating the
// signature but ignoring time-based claim validation (expiry, not-before).
// This is useful for logout flows where the access token may be expired.
func (j *JWTManager) ParseTokenClaims(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
