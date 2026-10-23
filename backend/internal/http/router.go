package http

import "net/http"

// NewRouter wires the HTTP surface.
// Currently: GET /health only.
func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", HealthHandler)
	return mux
}
