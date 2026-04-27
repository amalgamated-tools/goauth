package auth

import (
	"encoding/json"
	"net/http"
)

// jsonErrorBody is a small struct used instead of map[string]string to avoid
// allocating a map literal per call, reducing allocations without relying on
// exact `encoding/json` allocation behavior across Go versions.
type jsonErrorBody struct {
	Error string `json:"error"`
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonErrorBody{Error: message})
}
