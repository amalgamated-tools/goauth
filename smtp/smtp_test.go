package smtp

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// LoadConfig
// ---------------------------------------------------------------------------

func TestLoadConfig_defaults(t *testing.T) {
	// Ensure no SMTP env vars are set.
	for _, k := range []string{"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TLS"} {
		require.NoErrorf(t, os.Unsetenv(k), "unsetenv %s", k)
	}

	cfg := LoadConfig()

	require.Equal(t, "587", cfg.Port)
	require.Equal(t, "starttls", cfg.TLS)
	require.Empty(t, cfg.Host)
	require.Empty(t, cfg.From)
}

func TestLoadConfig_fromEnv(t *testing.T) {
	t.Setenv("SMTP_HOST", "mail.example.com")
	t.Setenv("SMTP_PORT", "465")
	t.Setenv("SMTP_USERNAME", "user@example.com")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("SMTP_FROM", "no-reply@example.com")
	t.Setenv("SMTP_TLS", "tls")

	cfg := LoadConfig()

	require.Equal(t, "mail.example.com", cfg.Host)
	require.Equal(t, "465", cfg.Port)
	require.Equal(t, "user@example.com", cfg.Username)
	require.Equal(t, "secret", cfg.Password)
	require.Equal(t, "no-reply@example.com", cfg.From)
	require.Equal(t, "tls", cfg.TLS)
}

// ---------------------------------------------------------------------------
// Enabled
// ---------------------------------------------------------------------------

func TestEnabled_true(t *testing.T) {
	cfg := Config{Host: "mail.example.com", From: "no-reply@example.com"}
	require.True(t, cfg.Enabled())
}

func TestEnabled_noHost(t *testing.T) {
	cfg := Config{From: "no-reply@example.com"}
	require.False(t, cfg.Enabled())
}

func TestEnabled_noFrom(t *testing.T) {
	cfg := Config{Host: "mail.example.com"}
	require.False(t, cfg.Enabled())
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_success(t *testing.T) {
	cfg := Config{
		Host: "mail.example.com",
		Port: "587",
		From: "no-reply@example.com",
		TLS:  "starttls",
	}
	p, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, "mail.example.com:587", p.Addr)
	require.Equal(t, "no-reply@example.com", p.From)
	require.Equal(t, "starttls", p.TLS)
}

func TestValidate_withDisplayName(t *testing.T) {
	cfg := Config{
		Host: "mail.example.com",
		Port: "587",
		From: "My App <no-reply@example.com>",
		TLS:  "starttls",
	}
	p, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, "no-reply@example.com", p.From)
	require.NotEmpty(t, p.FromHeader)
}

func TestValidate_noHost(t *testing.T) {
	cfg := Config{Port: "587", From: "no-reply@example.com", TLS: "starttls"}
	_, err := cfg.Validate()
	require.Error(t, err)
}

func TestValidate_noFrom(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", TLS: "starttls"}
	_, err := cfg.Validate()
	require.Error(t, err)
}

func TestValidate_invalidFromAddress(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "not-an-email", TLS: "starttls"}
	_, err := cfg.Validate()
	require.Error(t, err)
}

func TestValidate_badPort(t *testing.T) {
	for _, port := range []string{"abc", "0", "99999", "-1"} {
		cfg := Config{Host: "mail.example.com", Port: port, From: "a@b.com", TLS: "starttls"}
		_, err := cfg.Validate()
		require.Errorf(t, err, "port %q", port)
	}
}

func TestValidate_defaultPortWhenEmpty(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "", From: "a@b.com", TLS: "starttls"}
	p, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, "mail.example.com:587", p.Addr)
}

func TestValidate_badTLSMode(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: "ssl"}
	_, err := cfg.Validate()
	require.Error(t, err)
}

func TestValidate_allTLSModes(t *testing.T) {
	for _, mode := range []string{"none", "starttls", "tls"} {
		cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: mode}
		p, err := cfg.Validate()
		require.NoErrorf(t, err, "mode %q", mode)
		require.Equalf(t, mode, p.TLS, "mode %q", mode)
	}
}

func TestValidate_defaultTLSWhenEmpty(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: ""}
	p, err := cfg.Validate()
	require.NoError(t, err)
	require.Equal(t, "starttls", p.TLS)
}

func TestValidate_withAuth(t *testing.T) {
	cfg := Config{
		Host:     "mail.example.com",
		Port:     "587",
		From:     "a@b.com",
		TLS:      "starttls",
		Username: "user",
		Password: "pass",
	}
	p, err := cfg.Validate()
	require.NoError(t, err)
	require.NotNil(t, p.Auth)
}

func TestValidate_noAuth(t *testing.T) {
	cfg := Config{Host: "mail.example.com", Port: "587", From: "a@b.com", TLS: "starttls"}
	p, err := cfg.Validate()
	require.NoError(t, err)
	require.Nil(t, p.Auth)
}

func TestValidate_portBoundaries(t *testing.T) {
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
		require.Equalf(t, tc.wantErr, err != nil, "port %q", tc.port)
	}
}
