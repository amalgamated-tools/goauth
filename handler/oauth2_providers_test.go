package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestResolveHTTPClient(t *testing.T) {
	t.Run("uses provided client", func(t *testing.T) {
		client := &http.Client{}

		require.Same(t, client, resolveHTTPClient(client))
	})

	t.Run("falls back to default client", func(t *testing.T) {
		require.Same(t, http.DefaultClient, resolveHTTPClient(nil))
	})
}

type rewriteTransport struct {
	base *httptest.Server
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.base.Listener.Addr().String()
	clone.Host = t.base.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(clone)
}

func TestGitHubProviderFetchUserInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+"test-token", r.Header.Get("Authorization"))
		require.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))

		switch r.URL.Path {
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":123,"login":"octocat","name":""}`))
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"email":"secondary@example.com","primary":false,"verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := &GitHubProvider{
		HTTPClient: &http.Client{Transport: rewriteTransport{base: srv}},
	}

	info, err := p.FetchUserInfo(context.Background(), &oauth2.Token{AccessToken: "test-token"})
	require.NoError(t, err)
	require.Equal(t, &OAuth2UserInfo{
		Subject:       "github:123",
		Email:         "primary@example.com",
		Name:          "octocat",
		EmailVerified: true,
	}, info)
}

func TestGoogleOAuth2ProviderFetchUserInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/oauth2/v3/userinfo", r.URL.Path)
		require.Equal(t, "Bearer "+"test-token", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"abc123","email":"user@example.com","email_verified":true,"name":"Test User"}`))
	}))
	t.Cleanup(srv.Close)

	p := &GoogleOAuth2Provider{
		HTTPClient: &http.Client{Transport: rewriteTransport{base: srv}},
	}

	info, err := p.FetchUserInfo(context.Background(), &oauth2.Token{AccessToken: "test-token"})
	require.NoError(t, err)
	require.Equal(t, &OAuth2UserInfo{
		Subject:       "google:abc123",
		Email:         "user@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}, info)
}
