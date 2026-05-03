package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// GitHubProvider is a ready-to-use OAuth2IdentityProvider for GitHub. It calls
// the GitHub REST API to fetch the authenticated user's profile and primary
// verified email. Subjects are prefixed with "github:" (e.g. "github:12345")
// so they do not collide with OIDC subjects or other providers.
//
// Required OAuth2 scopes: "read:user" and "user:email".
type GitHubProvider struct {
	// HTTPClient is used for API requests. Defaults to http.DefaultClient when nil.
	HTTPClient *http.Client
}

func (p *GitHubProvider) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

// FetchUserInfo fetches the GitHub user profile and primary verified email.
func (p *GitHubProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
	user, err := p.fetchGitHubUser(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub user: %w", err)
	}
	email, verified, err := p.fetchGitHubPrimaryEmail(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub email: %w", err)
	}
	name := user.Name
	if name == "" {
		name = user.Login
	}
	return &OAuth2UserInfo{
		Subject:       fmt.Sprintf("github:%d", user.ID),
		Email:         email,
		Name:          name,
		EmailVerified: verified,
	}, nil
}

type gitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

func (p *GitHubProvider) fetchGitHubUser(ctx context.Context, token *oauth2.Token) (*gitHubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub /user returned HTTP %d", resp.StatusCode)
	}
	var u gitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("decode GitHub user: %w", err)
	}
	return &u, nil
}

type gitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *GitHubProvider) fetchGitHubPrimaryEmail(ctx context.Context, token *oauth2.Token) (email string, verified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GitHub /user/emails returned HTTP %d", resp.StatusCode)
	}
	var emails []gitHubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("decode GitHub emails: %w", err)
	}
	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}
	return "", false, fmt.Errorf("no primary email found in GitHub response")
}

// GoogleOAuth2Provider is a ready-to-use OAuth2IdentityProvider for Google. It
// calls Google's userinfo endpoint instead of performing OIDC id_token
// verification. Use this as a fallback only; for new integrations prefer
// OIDCHandler with Google's OIDC discovery URL
// (https://accounts.google.com).
//
// Required OAuth2 scope: "https://www.googleapis.com/auth/userinfo.email".
type GoogleOAuth2Provider struct {
	// HTTPClient is used for API requests. Defaults to http.DefaultClient when nil.
	HTTPClient *http.Client
}

func (p *GoogleOAuth2Provider) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// FetchUserInfo fetches the Google user profile from the userinfo endpoint.
func (p *GoogleOAuth2Provider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo returned HTTP %d", resp.StatusCode)
	}
	var u googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("decode Google userinfo: %w", err)
	}
	return &OAuth2UserInfo{
		Subject:       u.Sub,
		Email:         u.Email,
		Name:          u.Name,
		EmailVerified: u.EmailVerified,
	}, nil
}
