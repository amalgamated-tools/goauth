package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GenerateTOTPSecret
// ---------------------------------------------------------------------------

func TestGenerateTOTPSecretLength(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 20 bytes → 32 unpadded base32 chars
	if len(secret) != 32 {
		t.Errorf("expected 32 chars, got %d", len(secret))
	}
}

func TestGenerateTOTPSecretIsBase32(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		t.Errorf("secret is not valid base32: %v", err)
	}
}

func TestGenerateTOTPSecretIsRandom(t *testing.T) {
	s1, _ := GenerateTOTPSecret()
	s2, _ := GenerateTOTPSecret()
	if s1 == s2 {
		t.Error("successive secrets should differ")
	}
}

// ---------------------------------------------------------------------------
// TOTPProvisioningURI
// ---------------------------------------------------------------------------

func TestTOTPProvisioningURIFormat(t *testing.T) {
	uri := TOTPProvisioningURI("JBSWY3DPEHPK3PXP", "alice@example.com", "MyApp")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("expected otpauth://totp/ prefix, got %q", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("expected secret param in URI: %q", uri)
	}
	if !strings.Contains(uri, "issuer=MyApp") {
		t.Errorf("expected issuer param in URI: %q", uri)
	}
	if !strings.Contains(uri, "digits=6") {
		t.Errorf("expected digits=6 in URI: %q", uri)
	}
	if !strings.Contains(uri, "period=30") {
		t.Errorf("expected period=30 in URI: %q", uri)
	}
	if !strings.Contains(uri, "algorithm=SHA1") {
		t.Errorf("expected algorithm=SHA1 in URI: %q", uri)
	}
}

func TestTOTPProvisioningURIContainsLabel(t *testing.T) {
	uri := TOTPProvisioningURI("SECRET", "user@test.com", "Issuer")
	// Label is "Issuer:user@test.com" (URL-encoded)
	if !strings.Contains(uri, "Issuer") {
		t.Errorf("expected issuer in label: %q", uri)
	}
}

func TestTOTPProvisioningURISpecialChars(t *testing.T) {
	uri := TOTPProvisioningURI("SECRET", "user+tag@example.com", "My App")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("expected otpauth://totp/ prefix, got %q", uri)
	}
	// Should not panic or produce an empty string.
	if uri == "" {
		t.Error("expected non-empty URI")
	}
}

// ---------------------------------------------------------------------------
// ValidateTOTP
// ---------------------------------------------------------------------------

func TestValidateTOTPCurrentStep(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(time.Now().Unix() / totpPeriod)
	code := hotpCode(keyBytes, step)

	ok, err := ValidateTOTP(secret, code)
	if err != nil {
		t.Fatalf("ValidateTOTP error: %v", err)
	}
	if !ok {
		t.Error("expected valid code for current step")
	}
}

func TestValidateTOTPPreviousStep(t *testing.T) {
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
	if err != nil {
		t.Fatalf("ValidateTOTP error: %v", err)
	}
	if !ok {
		t.Error("expected valid code for previous step (clock skew tolerance)")
	}
}

func TestValidateTOTPNextStep(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(time.Now().Unix() / totpPeriod)
	code := hotpCode(keyBytes, step+1)

	ok, err := ValidateTOTP(secret, code)
	if err != nil {
		t.Fatalf("ValidateTOTP error: %v", err)
	}
	if !ok {
		t.Error("expected valid code for next step (clock skew tolerance)")
	}
}

func TestValidateTOTPWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	ok, err := ValidateTOTP(secret, "000000")
	// "000000" is a valid format — may or may not match; we just ensure no error.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Generate the actual current code to confirm "000000" is (almost certainly) wrong.
	keyBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	step := uint64(time.Now().Unix() / totpPeriod)
	for delta := int64(-totpSkew); delta <= int64(totpSkew); delta++ {
		if hotpCode(keyBytes, uint64(int64(step)+delta)) == "000000" {
			t.Skip("000000 is the actual current code — skipping false-negative check")
		}
	}
	if ok {
		t.Error("expected invalid code")
	}
}

func TestValidateTOTPInvalidSecret(t *testing.T) {
	_, err := ValidateTOTP("not-valid-base32!!!", "123456")
	if err == nil {
		t.Error("expected error for invalid base32 secret")
	}
}

func TestValidateTOTPWrongCodeLength(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	// Codes that are not exactly 6 digits must be rejected without error.
	for _, code := range []string{"12345", "1234567", "", "abcdef"} {
		ok, err := ValidateTOTP(secret, code)
		if err != nil {
			t.Errorf("code %q: unexpected error: %v", code, err)
		}
		if ok {
			t.Errorf("code %q: expected invalid result for wrong-length code", code)
		}
	}
}

// ---------------------------------------------------------------------------
// hotpCode
// ---------------------------------------------------------------------------

// RFC 4226 Appendix D test vectors using the ASCII secret "12345678901234567890".
func TestHOTPCodeRFC4226Vectors(t *testing.T) {
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
		if got != tc.code {
			t.Errorf("counter=%d: expected %s, got %s", tc.counter, tc.code, got)
		}
	}
}
