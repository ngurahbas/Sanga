package doc

import (
	"context"
	"strings"
	"testing"

	"github.com/ngurahbas/Sanga/backend/internal/db"
	"github.com/ngurahbas/Sanga/backend/internal/user"
)

func setup(t *testing.T) (*Store, string, string, context.Context) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	us := &user.Store{DB: database}
	a, err := us.Create(ctx, "owner1", "human")
	if err != nil {
		t.Fatal(err)
	}
	b, err := us.Create(ctx, "reader1", "human")
	if err != nil {
		t.Fatal(err)
	}
	return &Store{DB: database}, a.ID, b.ID, ctx
}

func TestCreateValidation(t *testing.T) {
	s, owner, _, ctx := setup(t)
	if _, err := s.Create(ctx, owner, "  ", "# body", "", nil, nil); err == nil {
		t.Fatal("expected title error")
	}
	if _, err := s.Create(ctx, owner, "ok", "   ", "", nil, nil); err == nil {
		t.Fatal("expected body error")
	}
	if _, err := s.Create(ctx, owner, "ok", "# b", "secret", nil, nil); err == nil {
		t.Fatal("expected visibility error")
	}
	if _, err := s.Create(ctx, owner, "ok", "# b", "", []string{"BAD TAG!"}, nil); err == nil {
		t.Fatal("expected tag error")
	}
	big := strings.Repeat("x", MaxBodyBytes+1)
	if _, err := s.Create(ctx, owner, "ok", big, "", nil, nil); err == nil {
		t.Fatal("expected body size error")
	}
}

func TestCreateGetShares(t *testing.T) {
	s, owner, reader, ctx := setup(t)
	d, err := s.Create(ctx, owner, "Hello", "# hi", "private", []string{"Go", "go", "notes"}, []string{reader})
	if err != nil {
		t.Fatal(err)
	}
	if d.Visibility != VisibilityPrivate {
		t.Fatalf("visibility = %q", d.Visibility)
	}
	if len(d.Tags) != 2 || d.Tags[0] != "go" {
		t.Fatalf("tags = %v", d.Tags)
	}
	got, err := s.ByID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !CanRead(got, reader, false) {
		t.Fatal("shared reader should read")
	}
	if CanWrite(got, reader, false) {
		t.Fatal("shared reader should not write")
	}
	if !CanWrite(got, owner, false) {
		t.Fatal("owner should write")
	}
	if !CanRead(got, "stranger", true) {
		t.Fatal("admin should read")
	}
}

func TestListReadable(t *testing.T) {
	s, owner, reader, ctx := setup(t)
	if _, err := s.Create(ctx, owner, "pub", "b", "public", []string{"t1"}, nil); err != nil {
		t.Fatal(err)
	}
	priv, err := s.Create(ctx, owner, "priv", "b", "private", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := s.ListReadable(ctx, reader, false, ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("stranger sees %d, want 1", len(docs))
	}
	docs, err = s.ListReadable(ctx, owner, false, ListOptions{Visibility: "private"})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || docs[0].ID != priv.ID {
		t.Fatalf("owner private filter = %v", docs)
	}
	docs, err = s.ListReadable(ctx, owner, false, ListOptions{Tag: "T1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("tag filter = %d, want 1", len(docs))
	}
}
