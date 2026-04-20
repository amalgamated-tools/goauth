package auth

import (
	"encoding/base32"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// GenerateTOTPSecret
// ---------------------------------------------------------------------------

func TestGenerateTOTPSecret_length(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	// 20 bytes → 32 unpadded base32 chars
	require.Len(t, secret, 32)
}

func TestGenerateTOTPSecret_isBase32(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
}

func TestGenerateTOTPSecret_isRandom(t *testing.T) {
	s1, _ := GenerateTOTPSecret()
	s2, _ := GenerateTOTPSecret()
	require.NotEqual(t, s1, s2)
}

// ---------------------------------------------------------------------------
// TOTPProvisioningURI
// ---------------------------------------------------------------------------

func TestTOTPProvisioningURI_format(t *testing.T) {
	uri := TOTPProvisioningURI("JBSWY3DPEHPK3PXP", "alice@example.com", "MyApp")
	require.True(t, strings.HasPrefix(uri, "otpauth://totp/"))
	require.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
	require.Contains(t, uri, "issuer=MyApp")
	require.Contains(t, uri, "digits=6")
	require.Contains(t, uri, "period=30")
	require.Contains(t, uri, "algorithm=SHA1")
}

func TestTOTPProvisioningURI_containsLabel(t *testing.T) {
	uri := TOTPProvisioningURI("SECRET", "user@test.com", "Issuer")
	// Label is "Issuer:user@test.com" (URL-encoded)
	require.Contains(t, uri, "Issuer")
}

func TestTOTPProvisioningURI_specialChars(t *testing.T) {
	uri := TOTPProvisioningURI("SECRET", "user+tag@example.com", "My App")
	require.True(t, strings.HasPrefix(uri, "otpauth://totp/"))
	// Should not panic or produce an empty string.
	require.NotEmpty(t, uri)
}

// ---------------------------------------------------------------------------
// ValidateTOTP
// ---------------------------------------------------------------------------

func TestValidateTOTP_currentStep(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(time.Now().Unix() / totpPeriod)
	code := hotpCode(keyBytes, step)

	ok, err := ValidateTOTP(secret, code)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateTOTP_previousStep(t *testing.T) {
	// Skip if within the last second of a step period: if a boundary is crossed
	// between capturing `step` and the ValidateTOTP call, step-1 falls outside
	// the ±1 skew window and the test would fail spuriously.
	now := time.Now()
	if now.Unix()%totpPeriod >= totpPeriod-1 {
		t.Skip("too close to step boundary")
	}
	secret, _ := GenerateTOTPSecret()
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(now.Unix() / totpPeriod)
	code := hotpCode(keyBytes, step-1)

	ok, err := ValidateTOTP(secret, code)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateTOTP_nextStep(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(time.Now().Unix() / totpPeriod)
	code := hotpCode(keyBytes, step+1)

	ok, err := ValidateTOTP(secret, code)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateTOTP_wrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	ok, err := ValidateTOTP(secret, "000000")
	// "000000" is a valid format — may or may not match; we just ensure no error.
	require.NoError(t, err)
	// Generate the actual current code to confirm "000000" is (almost certainly) wrong.
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(time.Now().Unix() / totpPeriod)
	for delta := int64(-totpSkew); delta <= int64(totpSkew); delta++ {
		if hotpCode(keyBytes, uint64(int64(step)+delta)) == "000000" {
			t.Skip("000000 is the actual current code — skipping false-negative check")
		}
	}
	require.False(t, ok)
}

func TestValidateTOTP_invalidSecret(t *testing.T) {
	_, err := ValidateTOTP("not-valid-base32!!!", "123456")
	require.Error(t, err)
}

func TestValidateTOTP_wrongCodeLength(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	// Codes that are not exactly 6 digits must be rejected without error.
	for _, code := range []string{"12345", "1234567", "", "abcdef"} {
		ok, err := ValidateTOTP(secret, code)
		require.NoErrorf(t, err, "code %q", code)
		require.Falsef(t, ok, "code %q", code)
	}
}

// ---------------------------------------------------------------------------
// hotpCode
// ---------------------------------------------------------------------------

// RFC 4226 Appendix D test vectors using the ASCII secret "12345678901234567890".
func TestHOTPCode_rfc4226Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	vectors := []struct {
		counter uint64
		code    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}
	for _, tc := range vectors {
		got := hotpCode(key, tc.counter)
		require.Equalf(t, tc.code, got, "counter=%d", tc.counter)
	}
}

// ---------------------------------------------------------------------------
// Constant consistency
// ---------------------------------------------------------------------------

func TestTotpModuloMatchesDigits(t *testing.T) {
	require.Equal(t, uint32(math.Pow10(totpDigits)), uint32(totpModulo),
		"totpModulo must equal 10^totpDigits; update totpModulo when totpDigits changes")
}
