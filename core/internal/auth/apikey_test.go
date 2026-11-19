package auth

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ngurahbas/Sanga/core/internal/db"
	"github.com/ngurahbas/Sanga/core/internal/user"
)

func TestIssueAuthenticateRevoke(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	us := user.NewStore(database)
	u, err := us.Create(ctx, "agent-1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	ks := NewStore(database)

	issued, err := ks.Issue(ctx, u.ID, "default")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Raw == "" || len(issued.Raw) < 20 {
		t.Fatal("expected raw key")
	}

	if len(issued.KeyPrefix) != 8 {
		t.Fatalf("prefix len = %d, want 8", len(issued.KeyPrefix))
	}

	got, err := ks.Authenticate(ctx, issued.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != u.ID {
		t.Fatal("wrong user")
	}

	if _, err := ks.Authenticate(ctx, issued.Key.ID+".wrong"); err == nil {
		t.Fatal("expected auth failure")
	}

	if err := ks.Revoke(ctx, issued.Key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Authenticate(ctx, issued.Raw); err == nil {
		t.Fatal("expected revoked failure")
	}
}

func TestIssueCapIsAtomic(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	us := user.NewStore(database)
	u, err := us.Create(ctx, "agent-1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	ks := NewStore(database)

	start := make(chan struct{})
	errs := make([]error, 40)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = ks.Issue(ctx, u.ID, "concurrent")
		}(i)
	}
	close(start)
	wg.Wait()

	issued := 0
	for _, err := range errs {
		switch {
		case err == nil:
			issued++
		case !errors.Is(err, ErrKeyLimit):
			t.Fatalf("issue error = %v", err)
		}
	}
	if issued != MaxActiveKeys {
		t.Fatalf("issued = %d, want %d", issued, MaxActiveKeys)
	}
	active, err := ks.ActiveCount(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active != MaxActiveKeys {
		t.Fatalf("active = %d, want %d", active, MaxActiveKeys)
	}
}

func TestCannotRevokeLastAdminKey(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	us := user.NewStore(database)
	ks := NewStore(database)
	first, err := us.Create(ctx, "admin-a", "admin")
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := ks.Issue(ctx, first.ID, "only")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Revoke(ctx, firstKey.Key.ID); !errors.Is(err, ErrLastAdminKey) {
		t.Fatalf("revoke last admin key = %v, want ErrLastAdminKey", err)
	}

	second, err := us.Create(ctx, "admin-b", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Issue(ctx, second.ID, "second"); err != nil {
		t.Fatal(err)
	}
	if err := ks.Revoke(ctx, firstKey.Key.ID); err != nil {
		t.Fatalf("revoke with another admin key: %v", err)
	}
}
