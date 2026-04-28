// Package smtp provides a generic SMTP email sender. It handles TLS negotiation,
// authentication, and connection management. Templates and email content are the
// consuming application's responsibility.
package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	netsmtp "net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
	TLS      string // "none", "starttls" (default), "tls"
}

// Params holds validated parameters ready for sending.
type Params struct {
	Addr string
	From string // bare email for SMTP envelope
	// FromHeader is populated by Validate() as an RFC 5322-formatted address
	// string. When the configured From address includes a display name it is
	// set to "Display Name <addr@example.com>"; otherwise it is the bare email
	// address (e.g. "addr@example.com"). Use this value as the From header in
	// outgoing messages.
	FromHeader string
	TLS        string
	Auth       netsmtp.Auth
}

// LoadConfig reads SMTP configuration from environment variables.
func LoadConfig() Config {
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	tlsMode := os.Getenv("SMTP_TLS")
	if tlsMode == "" {
		tlsMode = "starttls"
	}
	return Config{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
		TLS:      tlsMode,
	}
}

// Enabled returns true if SMTP host and from are configured.
func (c Config) Enabled() bool {
	return c.Host != "" && c.From != ""
}

// Validate checks the config and returns Params ready for Send.
func (c Config) Validate() (Params, error) {
	if c.Host == "" {
		return Params{}, fmt.Errorf("smtp host required")
	}
	from := strings.TrimSpace(c.From)
	if from == "" {
		return Params{}, fmt.Errorf("from address required")
	}
	parsed, err := mail.ParseAddress(from)
	if err != nil {
		return Params{}, fmt.Errorf("invalid from address: %w", err)
	}
	fromHeader := parsed.Address
	if parsed.Name != "" {
		fromHeader = parsed.String()
	}
	port := strings.TrimSpace(c.Port)
	if port == "" {
		port = "587"
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return Params{}, fmt.Errorf("port must be 1-65535")
	}
	tlsMode := strings.TrimSpace(c.TLS)
	if tlsMode == "" {
		tlsMode = "starttls"
	}
	if tlsMode != "none" && tlsMode != "starttls" && tlsMode != "tls" {
		return Params{}, fmt.Errorf("tls must be none, starttls, or tls")
	}
	var smtpAuth netsmtp.Auth
	if c.Username != "" && c.Password != "" {
		smtpAuth = netsmtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	return Params{
		Addr: net.JoinHostPort(c.Host, strconv.Itoa(portNum)),
		From: parsed.Address, FromHeader: fromHeader,
		TLS: tlsMode, Auth: smtpAuth,
	}, nil
}

const sessionTimeout = 30 * time.Second

// Send delivers a single email message.
func Send(ctx context.Context, params Params, to string, msg []byte) error {
	host, _, err := net.SplitHostPort(params.Addr)
	if err != nil {
		return fmt.Errorf("smtp invalid address: %w", err)
	}
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var conn net.Conn
	switch params.TLS {
	case "tls":
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", params.Addr)
	default:
		conn, err = dialer.DialContext(ctx, "tcp", params.Addr)
	}
	if err != nil {
		return fmt.Errorf("smtp connection failed: %w", err)
	}

	deadline := time.Now().Add(sessionTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	client, err := netsmtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	if params.TLS == "starttls" {
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("smtp STARTTLS failed: %w", err)
		}
	}
	if params.Auth != nil {
		if err := client.Auth(params.Auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}
	if err := client.Mail(params.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close failed: %w", err)
	}
	return client.Quit()
}
