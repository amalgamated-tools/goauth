# Tutorial: Build your first goauth server

This tutorial walks you through building a minimal but fully working HTTP authentication server using goauth. By the end you will have:

- email/password signup and login
- JWT access tokens and server-side sessions with refresh tokens
- protected routes that require authentication

**Prerequisites**: Go 1.26 or later installed.

---

## 1. Create the module

```sh
mkdir myapp && cd myapp
go mod init myapp
go get github.com/amalgamated-tools/goauth
```

---

## 2. Implement the store interfaces

goauth is router- and database-agnostic. You supply data access by implementing the store interfaces it defines. For this tutorial, use simple in-memory maps.

Create `store.go`:

```go
package main

import (
    "context"
    "sync"
    "time"

    "github.com/amalgamated-tools/goauth/auth"
)

// --- UserStore ---

type userStore struct {
    mu    sync.Mutex
    users map[string]*auth.User // keyed by ID
    byEmail map[string]*auth.User
    seq  int
}

func newUserStore() *userStore {
    return &userStore{
        users:   make(map[string]*auth.User),
        byEmail: make(map[string]*auth.User),
    }
}

func (s *userStore) nextID() string {
    s.seq++
    return fmt.Sprintf("u%d", s.seq)
}

func (s *userStore) CreateUser(_ context.Context, name, email, passwordHash string) (*auth.User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, ok := s.byEmail[email]; ok {
        return nil, auth.ErrEmailExists
    }
    u := &auth.User{ID: s.nextID(), Name: name, Email: email, PasswordHash: passwordHash, CreatedAt: time.Now()}
    s.users[u.ID] = u
    s.byEmail[email] = u
    return u, nil
}

func (s *userStore) CreateOIDCUser(_ context.Context, name, email, oidcSubject string) (*auth.User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, ok := s.byEmail[email]; ok {
        return nil, auth.ErrEmailExists
    }
    u := &auth.User{ID: s.nextID(), Name: name, Email: email, OIDCSubject: &oidcSubject, CreatedAt: time.Now()}
    s.users[u.ID] = u
    s.byEmail[email] = u
    return u, nil
}

func (s *userStore) FindByEmail(_ context.Context, email string) (*auth.User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    u, ok := s.byEmail[email]
    if !ok {
        return nil, auth.ErrNotFound
    }
    return u, nil
}

func (s *userStore) FindByID(_ context.Context, id string) (*auth.User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    u, ok := s.users[id]
    if !ok {
        return nil, auth.ErrNotFound
    }
    return u, nil
}

func (s *userStore) FindByOIDCSubject(_ context.Context, subject string) (*auth.User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    for _, u := range s.users {
        if u.OIDCSubject != nil && *u.OIDCSubject == subject {
            return u, nil
        }
    }
    return nil, auth.ErrNotFound
}

func (s *userStore) LinkOIDCSubject(_ context.Context, userID, oidcSubject string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    u, ok := s.users[userID]
    if !ok {
        return auth.ErrNotFound
    }
    u.OIDCSubject = &oidcSubject
    return nil
}

func (s *userStore) UpdatePassword(_ context.Context, userID, passwordHash string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    u, ok := s.users[userID]
    if !ok {
        return auth.ErrNotFound
    }
    u.PasswordHash = passwordHash
    return nil
}

func (s *userStore) UpdateName(_ context.Context, userID, name string) (*auth.User, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    u, ok := s.users[userID]
    if !ok {
        return nil, auth.ErrNotFound
    }
    u.Name = name
    return u, nil
}

func (s *userStore) IsAdmin(_ context.Context, userID string) (bool, error) {
    return false, nil // no admins in this tutorial
}

func (s *userStore) CountUsers(_ context.Context) (int, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    return len(s.users), nil
}

// --- SessionStore ---

type sessionStore struct {
    mu       sync.Mutex
    sessions map[string]*auth.Session
    byHash   map[string]*auth.Session
    seq      int
}

func newSessionStore() *sessionStore {
    return &sessionStore{
        sessions: make(map[string]*auth.Session),
        byHash:   make(map[string]*auth.Session),
    }
}

func (s *sessionStore) nextID() string {
    s.seq++
    return fmt.Sprintf("s%d", s.seq)
}

func (s *sessionStore) CreateSession(_ context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*auth.Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    sess := &auth.Session{
        ID: s.nextID(), UserID: userID, RefreshTokenHash: refreshTokenHash,
        UserAgent: userAgent, IPAddress: ipAddress, ExpiresAt: expiresAt, CreatedAt: time.Now(),
    }
    s.sessions[sess.ID] = sess
    s.byHash[refreshTokenHash] = sess
    return sess, nil
}

func (s *sessionStore) FindSessionByID(_ context.Context, id string) (*auth.Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    sess, ok := s.sessions[id]
    if !ok {
        return nil, auth.ErrNotFound
    }
    return sess, nil
}

func (s *sessionStore) FindSessionByRefreshTokenHash(_ context.Context, hash string) (*auth.Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    sess, ok := s.byHash[hash]
    if !ok {
        return nil, auth.ErrNotFound
    }
    return sess, nil
}

func (s *sessionStore) ListSessionsByUser(_ context.Context, userID string) ([]auth.Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    var result []auth.Session
    for _, sess := range s.sessions {
        if sess.UserID == userID {
            result = append(result, *sess)
        }
    }
    return result, nil
}

func (s *sessionStore) DeleteSession(_ context.Context, id, userID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    sess, ok := s.sessions[id]
    if !ok || sess.UserID != userID {
        return auth.ErrNotFound
    }
    delete(s.byHash, sess.RefreshTokenHash)
    delete(s.sessions, id)
    return nil
}

func (s *sessionStore) DeleteAllSessionsByUser(_ context.Context, userID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    for id, sess := range s.sessions {
        if sess.UserID == userID {
            delete(s.byHash, sess.RefreshTokenHash)
            delete(s.sessions, id)
        }
    }
    return nil
}

func (s *sessionStore) DeleteExpiredSessions(_ context.Context) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    now := time.Now()
    for id, sess := range s.sessions {
        if sess.ExpiresAt.Before(now) {
            delete(s.byHash, sess.RefreshTokenHash)
            delete(s.sessions, id)
        }
    }
    return nil
}
```

---

## 3. Wire up the server

Create `main.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/amalgamated-tools/goauth/auth"
    "github.com/amalgamated-tools/goauth/handler"
    "github.com/amalgamated-tools/goauth/maintenance"
)

func main() {
    // 1. Create a JWT manager.
    //    Use a secret of at least 32 bytes. In production, load this from an
    //    environment variable or secrets manager and rotate it on a schedule.
    jwtMgr, err := auth.NewJWTManager(
        "replace-this-with-a-32-byte-secret!",
        15*time.Minute, // short-lived access tokens
        "myapp",
    )
    if err != nil {
        log.Fatal("jwt:", err)
    }

    // 2. Create the in-memory stores.
    users    := newUserStore()
    sessions := newSessionStore()

    // 3. Configure the AuthHandler.
    authH := &handler.AuthHandler{
        Users:             users,
        JWT:               jwtMgr,
        CookieName:        "session",
        SecureCookies:     false, // set true in production (HTTPS only)
        Sessions:          sessions,
        RefreshTokenTTL:   7 * 24 * time.Hour,
        RefreshCookieName: "refresh",
    }
    if err := authH.Validate(); err != nil {
        log.Fatal("authH:", err)
    }

    // 4. Build a plain net/http mux.
    mux := http.NewServeMux()

    // Public routes.
    mux.HandleFunc("POST /auth/signup",  authH.Signup)
    mux.HandleFunc("POST /auth/login",   authH.Login)
    mux.HandleFunc("POST /auth/logout",  authH.Logout)
    mux.HandleFunc("POST /auth/refresh", authH.RefreshToken)

    // Protected routes — wrapped with the auth middleware.
    cfg := auth.Config{CookieName: "session", Sessions: sessions}
    protect := auth.Middleware(jwtMgr, cfg, nil) // nil = no API keys

    mux.Handle("GET /auth/me",       protect(http.HandlerFunc(authH.Me)))
    mux.Handle("PUT /auth/me",       protect(http.HandlerFunc(authH.UpdateProfile)))
    mux.Handle("POST /auth/password", protect(http.HandlerFunc(authH.ChangePassword)))

    // 5. Start the maintenance background worker.
    ctx := context.Background()
    stop := maintenance.StartCleanup(ctx, 10*time.Minute,
        sessions.DeleteExpiredSessions,
    )
    defer stop()

    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## 4. Run and test

Start the server:

```sh
go run .
```

### Sign up

```sh
curl -s -c cookies.txt -X POST http://localhost:8080/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice","email":"alice@example.com","password":"secret123"}'
```

Expected response (HTTP 201):

```json
{
  "token": "<jwt>",
  "refresh_token": "<refresh>",
  "user": {"id":"u1","name":"Alice","email":"alice@example.com","oidc_linked":false,"is_admin":false,"email_verified":false}
}
```

### Log in

```sh
curl -s -c cookies.txt -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123"}'
```

### Fetch the current user

The access token is stored in the `session` cookie by the login endpoint. Pass it along:

```sh
curl -s -b cookies.txt http://localhost:8080/auth/me
```

### Refresh the access token

```sh
curl -s -c cookies.txt -b cookies.txt -X POST http://localhost:8080/auth/refresh
```

### Log out

```sh
curl -s -b cookies.txt -X POST http://localhost:8080/auth/logout
```

---

## Next steps

Now that you have the basics working, explore the rest of the library:

| Goal | Where to go |
|---|---|
| Add social login (GitHub, Google, …) | [Generic OAuth2](handler/oauth2.md) · [OIDC / SSO](handler/oidc.md) |
| Add passwordless magic-link login | [Magic Links](handler/magic-links.md) |
| Add hardware passkey support | [Passkeys (WebAuthn)](handler/passkeys.md) |
| Add TOTP / authenticator-app MFA | [TOTP](handler/totp.md) |
| Add email verification | [Email Verification](handler/email-verification.md) |
| Add password reset via email | [Password Reset](handler/password-reset.md) |
| Issue and validate API keys | [API Keys](handler/api-keys.md) |
| Add role-based access control | [RBAC](auth/rbac.md) |
| Encrypt sensitive fields at rest | [Crypto Utilities](auth/crypto.md) |
| Configure SMTP for email delivery | [SMTP package](smtp.md) |
| Harden your deployment | [Security Notes](security.md) |
