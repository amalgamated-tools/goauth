# `smtp` package

The `smtp` package provides SMTP email delivery with TLS/STARTTLS support, configured via environment variables.

## Import path

```go
import "github.com/amalgamated-tools/goauth/smtp"
```

## Usage

```go
cfg := smtp.LoadConfig() // reads SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, SMTP_TLS

if cfg.Enabled() {
    params, err := cfg.Validate()
    // ...
    err = smtp.Send(ctx, params, "recipient@example.com", rawMIMEMessage)
}
```

`smtp.Send` accepts a raw RFC 2822/MIME message as `[]byte`. Composing message bodies and templates is left to the consuming application.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | *(required)* | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | | Auth username (omit for unauthenticated) |
| `SMTP_PASSWORD` | | Auth password |
| `SMTP_FROM` | *(required)* | Sender address, RFC 5322 format (`Name <addr>` or bare address) |
| `SMTP_TLS` | `starttls` | TLS mode: `none`, `starttls`, or `tls` |

## Security and timeouts

- **TLS minimum version:** TLS 1.2 is enforced for both `tls` and `starttls` modes. Plain-text (`none`) disables TLS entirely and should only be used in trusted local environments.
- **Connection dial timeout:** 10 seconds.
- **Session timeout:** 30 seconds (measured from the moment the TCP connection is established). If the calling context has a shorter deadline, that deadline takes precedence.
