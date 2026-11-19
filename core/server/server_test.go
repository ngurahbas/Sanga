package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ngurahbas/Sanga/core/internal/db"
)

func TestNewHandler(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewHandler(database))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != `{"status":"ok"}` {
		t.Fatalf("health = %d %q", res.StatusCode, body)
	}
}
