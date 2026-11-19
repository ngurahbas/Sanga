package user

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ngurahbas/Sanga/core/internal/db"
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
	s := NewStore(database)
	ctx := context.Background()

	u, err := s.Create(ctx, "Baskara", "human")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "baskara" {
		t.Fatalf("username = %q, want normalized baskara", u.Username)
	}

	got, err := s.ByUsername(ctx, "BASKARA")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID {
		t.Fatal("lookup mismatch")
	}

	if _, err := s.Create(ctx, "baskara", "human"); err == nil {
		t.Fatal("expected duplicate username error")
	}

	if _, err := s.Create(ctx, "ok-name", "superuser"); err == nil {
		t.Fatal("expected bad role error")
	}
	if _, err := s.Create(ctx, "ab", "human"); err == nil {
		t.Fatal("expected bad username error")
	}
}

func TestDeleteCannotRemoveLastAdminConcurrently(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	s := NewStore(database)
	ctx := context.Background()
	first, err := s.Create(ctx, "admin-a", "admin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(ctx, "admin-b", "admin")
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, id := range []string{first.ID, second.ID} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			<-start
			errs[i] = s.Delete(ctx, id)
		}(i, id)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("delete error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful deletes = %d, want 1", successes)
	}
	n, err := s.CountAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("admins = %d, want 1", n)
	}
}
