package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

func resolveHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

func fetchOAuth2JSON(
	ctx context.Context,
	client *http.Client,
	token *oauth2.Token,
	url, accept, statusErr, decodeErr string,
	dst any,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := resolveHTTPClient(client).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", statusErr, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", decodeErr, err)
	}
	return nil
}

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
	var u gitHubUser
	if err := fetchOAuth2JSON(
		ctx,
		p.HTTPClient,
		token,
		"https://api.github.com/user",
		"application/vnd.github+json",
		"GitHub /user",
		"decode GitHub user",
		&u,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

type gitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *GitHubProvider) fetchGitHubPrimaryEmail(ctx context.Context, token *oauth2.Token) (email string, verified bool, err error) {
	var emails []gitHubEmail
	if err := fetchOAuth2JSON(
		ctx,
		p.HTTPClient,
		token,
		"https://api.github.com/user/emails",
		"application/vnd.github+json",
		"GitHub /user/emails",
		"decode GitHub emails",
		&emails,
	); err != nil {
		return "", false, err
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

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// FetchUserInfo fetches the Google user profile from the userinfo endpoint.
func (p *GoogleOAuth2Provider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
	var u googleUserInfo
	if err := fetchOAuth2JSON(
		ctx,
		p.HTTPClient,
		token,
		"https://www.googleapis.com/oauth2/v3/userinfo",
		"",
		"google userinfo",
		"decode Google userinfo",
		&u,
	); err != nil {
		return nil, err
	}
	return &OAuth2UserInfo{
		Subject:       "google:" + u.Sub,
		Email:         u.Email,
		Name:          u.Name,
		EmailVerified: u.EmailVerified,
	}, nil
}
