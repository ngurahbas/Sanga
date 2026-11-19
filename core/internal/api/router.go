package api

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/ngurahbas/Sanga/core/internal/httpx"
)

func NewRouter(database *sql.DB) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", HealthHandler)
	mux.HandleFunc("GET /ready", readyHandler(database))
	mountUsers(mux, database)
	mountDocs(mux, database)
	return mux
}

func readyHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := database.PingContext(ctx); err != nil {
			httpx.WriteErr(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
