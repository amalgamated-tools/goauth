package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// jsonErrorBody is a small struct used instead of map[string]string to avoid
// allocating a map literal per call, reducing allocations without relying on
// exact `encoding/json` allocation behavior across Go versions.
type jsonErrorBody struct {
	Error string `json:"error"`
}

func jsonError(ctx context.Context, w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(jsonErrorBody{Error: message}); err != nil {
		slog.ErrorContext(ctx, "failed to encode JSON error response", slog.Any("error", err))
	}
}
