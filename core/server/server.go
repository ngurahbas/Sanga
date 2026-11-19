package server

import (
	"database/sql"
	"net/http"

	"github.com/ngurahbas/Sanga/core/internal/api"
)

func NewHandler(database *sql.DB) http.Handler {
	return api.NewRouter(database)
}
