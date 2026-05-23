package handler

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
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
