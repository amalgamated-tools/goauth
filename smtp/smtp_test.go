package smtp

import (
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// LoadConfig
// ---------------------------------------------------------------------------

func TestLoadConfigDefaults(t *testing.T) {
	// Ensure no SMTP env vars are set.
	_ = os.Unsetenv("SMTP_HOST")
	_ = os.Unsetenv("SMTP_PORT")
	_ = os.Unsetenv("SMTP_USERNAME")
	_ = os.Unsetenv("SMTP_PASSWORD")
	_ = os.Unsetenv("SMTP_FROM")
	_ = os.Unsetenv("SMTP_TLS")

	cfg := LoadConfig()

	if cfg.Port != "587" {
		t.Errorf("expected default port 587, got %q", cfg.Port)
	}
	if cfg.TLS != "starttls" {
		t.Errorf("expected default TLS mode starttls, got %q", cfg.TLS)
	}
	if cfg.Host != "" || cfg.From != "" {
		t.Errorf("expected empty host and from, got host=%q from=%q", cfg.Host, cfg.From)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("SMTP_HOST", "mail.example.com")
	t.Setenv("SMTP_PORT", "465")
	t.Setenv("SMTP_USERNAME", "user@example.com")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("SMTP_FROM", "no-reply@example.com")
	t.Setenv("SMTP_TLS", "tls")

	cfg := LoadConfig()

	if cfg.Host != "mail.example.com" {
		t.Errorf("expected host mail.example.com, got %q", cfg.Host)
	}
	if cfg.Port != "465" {
		t.Errorf("expected port 465, got %q", cfg.Port)
	}
	if cfg.Username != "user@example.com" {
		t.Errorf("expected username, got %q", cfg.Username)
	}
	if cfg.Password != "secret" {
		t.Errorf("expected password, got %q", cfg.Password)
	}
	if cfg.From != "no-reply@example.com" {
		t.Errorf("expected from, got %q", cfg.From)
	}
	if cfg.TLS != "tls" {
		t.Errorf("expected TLS mode tls, got %q", cfg.TLS)
	}
}

// ---------------------------------------------------------------------------
// Enabled
// ---------------------------------------------------------------------------

func TestEnabledTrue(t *testing.T) {
	cfg := Config{Host: "mail.example.com", From: "no-reply@example.com"}
	if !cfg.Enabled() {
		t.Error("expected Enabled()=true when both Host and From are set")
	}
}

func TestEnabledNoHost(t *testing.T) {
	cfg := Config{From: "no-reply@example.com"}
	if cfg.Enabled() {
		t.Error("expected Enabled()=false when Host is empty")
	}
}

func TestEnabledNoFrom(t *testing.T) {
	cfg := Config{Host: "mail.example.com"}
	if cfg.Enabled() {
		t.Error("expected Enabled()=false when From is empty")
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidateSuccess(t *testing.T) {
	cfg := Config{
		Host: "mail.example.com",
		Port: "587",
		From: "no-reply@example.com",
		TLS:  "starttls",
	}
	p, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Addr != "mail.example.com:587" {
		t.Errorf("expected addr mail.example.com:587, got %q", p.Addr)
	}
	if p.From != "no-reply@example.com" {
		t.Errorf("expected from no-reply@example.com, got %q", p.From)
	}
	if p.TLS != "starttls" {
		t.Errorf("expected TLS starttls, got %q", p.TLS)
	}
}

func TestValidateWithDisplayName(t *testing.T) {
	cfg := Config{
		Host: "mail.example.com",
		Port: "587",
		From: "My App <no-reply@example.com>",
		TLS:  "starttls",
	}
	p, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.From != "no-reply@example.com" {
		t.Errorf("expected bare address, got %q", p.From)
	}
	if p.FromHeader == "" {
		t.Error("expected non-empty FromHeader when display name is set")
	}
}

func TestValidateNoHost(t *testing.T) {
	cfg := Config{Port: "587", From: "no-reply@example.com", TLS: "starttls"}
	_, err := cfg.Validate()
	if err == nil {
		t.Error("expected error when Host is empty")
	}
}

func TestValidateNoFrom(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", TLS: "starttls"}
	_, err := cfg.Validate()
	if err == nil {
		t.Error("expected error when From is empty")
	}
}

func TestValidateInvalidFromAddress(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "not-an-email", TLS: "starttls"}
	_, err := cfg.Validate()
	if err == nil {
		t.Error("expected error for invalid from address")
	}
}

func TestValidateBadPort(t *testing.T) {
	for _, port := range []string{"abc", "0", "99999", "-1"} {
		cfg := Config{Host: "mail.example.com", Port: port, From: "a@b.com", TLS: "starttls"}
		_, err := cfg.Validate()
		if err == nil {
			t.Errorf("port %q: expected error", port)
		}
	}
}

func TestValidateDefaultPortWhenEmpty(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "", From: "a@b.com", TLS: "starttls"}
	p, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Addr != "mail.example.com:587" {
		t.Errorf("expected default port 587, got %q", p.Addr)
	}
}

func TestValidateBadTLSMode(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: "ssl"}
	_, err := cfg.Validate()
	if err == nil {
		t.Error("expected error for invalid TLS mode ssl")
	}
}

func TestValidateAllTLSModes(t *testing.T) {
	for _, mode := range []string{"none", "starttls", "tls"} {
		cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: mode}
		p, err := cfg.Validate()
		if err != nil {
			t.Errorf("mode %q: unexpected error: %v", mode, err)
		}
		if p.TLS != mode {
			t.Errorf("mode %q: expected TLS=%q, got %q", mode, mode, p.TLS)
		}
	}
}

func TestValidateDefaultTLSWhenEmpty(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: ""}
	p, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.TLS != "starttls" {
		t.Errorf("expected default TLS starttls, got %q", p.TLS)
	}
}

func TestValidateWithAuth(t *testing.T) {
	cfg := Config{
		Host:     "mail.example.com",
		Port:     "587",
		From:     "a@b.com",
		TLS:      "starttls",
		Username: "user",
		Password: "pass",
	}
	p, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Auth == nil {
		t.Error("expected non-nil auth when username and password are set")
	}
}

func TestValidateNoAuth(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: "starttls"}
	p, err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Auth != nil {
		t.Error("expected nil auth when no credentials are provided")
	}
}

func TestValidatePortBoundaries(t *testing.T) {
	for _, tc := range []struct {
		port    string
		wantErr bool
	}{
		{"1", false},
		{"65535", false},
		{"65536", true},
		{"0", true},
	} {
		cfg := Config{Host: "h", Port: tc.port, From: "a@b.com", TLS: "starttls"}
		_, err := cfg.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("port %q: wantErr=%v, got err=%v", tc.port, tc.wantErr, err)
		}
	}
}
