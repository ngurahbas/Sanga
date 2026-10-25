package auth

import (
	"context"
	"testing"

	"github.com/ngurahbas/Sanga/backend/internal/db"
	"github.com/ngurahbas/Sanga/backend/internal/user"
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

	us := &user.Store{DB: database}
	u, err := us.Create(ctx, "agent-1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	ks := &Store{DB: database}

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
