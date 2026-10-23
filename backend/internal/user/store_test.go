package user

import (
	"context"
	"testing"

	"github.com/ngurahbas/Sanga/backend/internal/db"
)

func TestCreateAndLookup(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	s := &Store{DB: database}
	ctx := context.Background()

	u, err := s.Create(ctx, "Baskara", "human")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "baskara" {
		t.Fatalf("username = %q, want normalized baskara", u.Username)
	}

	// Case-insensitive lookup.
	got, err := s.ByUsername(ctx, "BASKARA")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID {
		t.Fatal("lookup mismatch")
	}

	// Duplicate must fail.
	if _, err := s.Create(ctx, "baskara", "human"); err == nil {
		t.Fatal("expected duplicate username error")
	}

	// Bad role and bad username must fail.
	if _, err := s.Create(ctx, "ok-name", "superuser"); err == nil {
		t.Fatal("expected bad role error")
	}
	if _, err := s.Create(ctx, "ab", "human"); err == nil {
		t.Fatal("expected bad username error")
	}
}
