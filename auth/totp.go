package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30        // seconds
	totpSkew   = 1         // time steps allowed before/after current
	totpModulo = 1_000_000 // 10^totpDigits; avoids float64 via math.Pow10 on the hot path
)

var (
	totpFormat    = fmt.Sprintf("%%0%dd", totpDigits)
	totpEncoding  = base32.StdEncoding.WithPadding(base32.NoPadding) // precomputed once; avoids per-call heap alloc on the hot path
	totpDigitsStr = strconv.Itoa(totpDigits)                         // precomputed; avoids a per-call alloc in TOTPProvisioningURI
	totpPeriodStr = strconv.Itoa(totpPeriod)                         // precomputed; avoids a per-call alloc in TOTPProvisioningURI
)

// TOTPEncoding returns the base32 encoding used for all TOTP secrets.
func TOTPEncoding() *base32.Encoding { return totpEncoding }

// GenerateTOTPSecret generates a cryptographically random 20-byte secret and
// returns it as an unpadded base32 string, which is the format expected by
// authenticator apps (Google Authenticator, Authy, etc.).
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return totpEncoding.EncodeToString(secret), nil
}

// TOTPProvisioningURI returns an otpauth:// URI suitable for encoding into a
// QR code and scanning with an authenticator app.
//
//   - secret:      unpadded base32-encoded TOTP secret (from GenerateTOTPSecret)
//   - accountName: the user identifier shown in the app, typically the email
//   - issuer:      the service name shown in the app
func TOTPProvisioningURI(secret, accountName, issuer string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(accountName)
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", totpDigitsStr)
	params.Set("period", totpPeriodStr)
	return "otpauth://totp/" + label + "?" + params.Encode()
}

// ValidateTOTP validates a numeric TOTP code against a base32-encoded secret.
// It checks the current time step as well as one step before and after to
// tolerate reasonable clock skew between the server and the authenticator app.
//
// WARNING: This function does not track previously-used codes. A valid code
// remains accepted for up to (2*totpSkew+1)*totpPeriod seconds (~90s). Callers
// that require replay protection must record and reject used codes within that
// window themselves.
func ValidateTOTP(secret, code string) (bool, error) {
	keyBytes, err := totpEncoding.DecodeString(secret)
	if err != nil {
		return false, fmt.Errorf("decode TOTP secret: %w", err)
	}
	if len(code) != totpDigits {
		return false, nil
	}
	mac := hmac.New(sha1.New, keyBytes) //nolint:gosec // required by RFC 6238
	step := time.Now().Unix() / totpPeriod
	for delta := int64(-totpSkew); delta <= int64(totpSkew); delta++ {
		if hotpCodeWithMAC(mac, uint64(step+delta)) == code {
			return true, nil
		}
	}
	return false, nil
}

// GenerateTOTPCode returns the TOTP code for secret at time t. It is provided
// for testing and tooling; applications should call ValidateTOTP instead.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	keyBytes, err := totpEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("decode TOTP secret: %w", err)
	}
	step := uint64(t.Unix() / totpPeriod)
	return hotpCode(keyBytes, step), nil
}

// hotpCodeWithMAC computes a single HOTP value per RFC 4226 §5.3 using a
// caller-provided HMAC. mac.Reset() is called first, allowing the same MAC to
// be reused across multiple counter values.
func hotpCodeWithMAC(mac hash.Hash, counter uint64) string {
	mac.Reset()
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	_, _ = mac.Write(msg[:])
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	truncated := (uint32(h[offset]&0x7f) << 24) |
		(uint32(h[offset+1]) << 16) |
		(uint32(h[offset+2]) << 8) |
		uint32(h[offset+3])

	otp := truncated % totpModulo
	return fmt.Sprintf(totpFormat, otp)
}

// hotpCode computes a single HOTP value per RFC 4226 §5.3.
func hotpCode(key []byte, counter uint64) string {
	mac := hmac.New(sha1.New, key) //nolint:gosec // required by RFC 6238
	return hotpCodeWithMAC(mac, counter)
}
