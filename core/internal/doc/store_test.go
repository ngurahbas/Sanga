package doc

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/ngurahbas/Sanga/core/internal/db"
	"github.com/ngurahbas/Sanga/core/internal/user"
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
	us := user.NewStore(database)
	a, err := us.Create(ctx, "owner1", "human")
	if err != nil {
		t.Fatal(err)
	}
	b, err := us.Create(ctx, "reader1", "human")
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(database), a.ID, b.ID, ctx
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

func TestUpdateRejectsEmptyVisibility(t *testing.T) {
	s, owner, _, ctx := setup(t)
	d, err := s.Create(ctx, owner, "Private", "body", "private", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	if _, err := s.Update(ctx, d.ID, Patch{Visibility: &empty}); !errors.Is(err, ErrInvalidVisibility) {
		t.Fatalf("empty visibility = %v, want ErrInvalidVisibility", err)
	}
	got, err := s.ByID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Visibility != VisibilityPrivate {
		t.Fatalf("visibility = %q, want private", got.Visibility)
	}
}

func TestUpdateOnlyChangesProvidedFields(t *testing.T) {
	s, owner, _, ctx := setup(t)
	d, err := s.Create(ctx, owner, "Original", "original body", "public", []string{"one"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	title := "Renamed"
	if _, err := s.Update(ctx, d.ID, Patch{Title: &title}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ByID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != title || got.Body != "original body" || len(got.Tags) != 1 || got.Tags[0] != "one" {
		t.Fatalf("updated doc = %+v", got)
	}
}

func TestCreateRejectsSharesOnPublicDocs(t *testing.T) {
	s, owner, reader, ctx := setup(t)
	if _, err := s.Create(ctx, owner, "Public", "body", "public", nil, []string{reader}); !errors.Is(err, ErrSharesRequirePrivate) {
		t.Fatalf("public shares = %v, want ErrSharesRequirePrivate", err)
	}
}

func TestAddShareRejectsOwnerAndLeavesNoOrphan(t *testing.T) {
	s, owner, _, ctx := setup(t)
	d, err := s.Create(ctx, owner, "Private", "body", "private", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddShare(ctx, d.ID, owner); !errors.Is(err, ErrCannotShareOwner) {
		t.Fatalf("share owner = %v, want ErrCannotShareOwner", err)
	}
	if err := s.AddShare(ctx, "missing", owner); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("share missing doc = %v, want sql.ErrNoRows", err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM doc_shares WHERE doc_id=?`, "missing").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("orphan shares = %d, want 0", count)
	}
}
