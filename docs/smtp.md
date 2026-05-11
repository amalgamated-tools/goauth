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

`smtp.Send` **automatically prepends a `From:` header** to the message before transmission. You do not need to add it yourself. If the message already contains a `From:` field, the automatic injection is skipped.

## `Params` fields

`cfg.Validate()` returns a `Params` value with two sender-related fields:

| Field | Value | Use |
|---|---|---|
| `From` | Bare email address (e.g. `sender@example.com`) | SMTP envelope (`MAIL FROM`) — handled internally by `smtp.Send` |
| `FromHeader` | RFC 5322-formatted address string | `From:` header injected automatically by `smtp.Send` |

When `SMTP_FROM` includes a display name (e.g. `My App <sender@example.com>`), `FromHeader` is the string produced by `mail.Address.String()`: the display name is quoted per RFC 5322 and RFC 2047-encoded when it contains non-ASCII characters (e.g. `"My App" <sender@example.com>`). When no display name is present, `FromHeader` is identical to `From`.

```go
params, err := cfg.Validate()
if err != nil { /* ... */ }

// smtp.Send automatically injects a "From: " header using params.FromHeader.
// Only include To, Subject, and body headers in the message.
msg := "To: recipient@example.com\r\n" +
    "Subject: Hello\r\n" +
    "\r\n" +
    "Message body.\r\n"

err = smtp.Send(ctx, params, "recipient@example.com", []byte(msg))
if err != nil { /* ... */ }
```

> **Note:** If your message already contains a `From:` field (detected by a case-insensitive header scan before the blank line), `smtp.Send` will not inject an additional one. This preserves any custom `From:` value you set explicitly.

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
