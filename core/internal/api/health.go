package api

import (
	"net/http"

	"github.com/ngurahbas/Sanga/core/internal/httpx"
)

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
