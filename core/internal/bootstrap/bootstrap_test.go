package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngurahbas/Sanga/core/internal/auth"
	"github.com/ngurahbas/Sanga/core/internal/db"
	"github.com/ngurahbas/Sanga/core/internal/user"
)

func TestGenerateWritesFile(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "admin.key")

	res, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Imported {
		t.Fatalf("expected generated create, got %+v", res)
	}
	if res.Raw == "" {
		t.Fatal("expected raw on generate")
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != res.Raw {
		t.Fatal("file content must equal returned raw")
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}

	ks := auth.NewStore(database)
	if _, err := ks.Authenticate(context.Background(), res.Raw); err != nil {
		t.Fatalf("authenticate generated: %v", err)
	}

	res2, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Created {
		t.Fatal("expected no-op on second run")
	}
}

func TestImportExistingFile(t *testing.T) {
	src, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := db.Migrate(src); err != nil {
		t.Fatal(err)
	}
	us := user.NewStore(src)
	u, err := us.Create(context.Background(), "tmp", "human")
	if err != nil {
		t.Fatal(err)
	}
	ks := auth.NewStore(src)
	issued, err := ks.Issue(context.Background(), u.ID, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}

	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "admin.key")
	if err := os.WriteFile(keyFile, []byte(issued.Raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Imported {
		t.Fatalf("expected import create, got %+v", res)
	}
	if res.Raw != "" {
		t.Fatal("import must not echo raw")
	}

	ks2 := auth.NewStore(database)
	got, err := ks2.Authenticate(context.Background(), issued.Raw)
	if err != nil {
		t.Fatalf("authenticate imported: %v", err)
	}
	us2 := user.NewStore(database)
	root, err := us2.ByID(context.Background(), got.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if root.Role != user.RoleAdmin || root.Username != "root" {
		t.Fatalf("root = %+v", root)
	}
}

func TestNoOpWhenAdminHasKey(t *testing.T) {
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
	root, err := us.Create(ctx, "root", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewStore(database).Issue(ctx, root.ID, "existing"); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(t.TempDir(), "admin.key")
	res, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created {
		t.Fatal("expected no-op when admin has an active key")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("must not create key file when admin has a key")
	}
}

func TestRecoversAdminWithoutActiveKey(t *testing.T) {
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
	root, err := us.Create(ctx, "root", "admin")
	if err != nil {
		t.Fatal(err)
	}
	ks := auth.NewStore(database)
	if _, err := ks.Issue(ctx, root.ID, "bootstrap"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE api_keys SET revoked_at=?`, "2026-01-01T00:00:00.000000000Z"); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(t.TempDir(), "admin.key")
	res, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Recovered || res.Imported {
		t.Fatalf("expected generated recovery, got %+v", res)
	}
	if _, err := ks.Authenticate(ctx, res.Raw); err != nil {
		t.Fatalf("recovered key: %v", err)
	}
}

func TestImportFailureRollsBackRootUser(t *testing.T) {
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
	other, err := us.Create(ctx, "other", "human")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := auth.NewStore(database).Issue(ctx, other.ID, "taken")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "admin.key")
	if err := os.WriteFile(keyFile, []byte(issued.Raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := EnsureAdmin(database, keyFile, "root"); err == nil {
		t.Fatal("expected import failure")
	}
	if _, err := us.ByUsername(ctx, "root"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("root lookup = %v, want no rows", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("users = %d, want 1", count)
	}
}

func TestInvalidFileFails(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "admin.key")
	if err := os.WriteFile(keyFile, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureAdmin(database, keyFile, "root"); err == nil {
		t.Fatal("expected error on invalid key file")
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("users = %d, want 0 (no partial create)", n)
	}
}

func TestRootNameConflictFails(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	us := user.NewStore(database)
	if _, err := us.Create(context.Background(), "root", "human"); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "admin.key")
	if _, err := EnsureAdmin(database, keyFile, "root"); err == nil {
		t.Fatal("expected error when root name is taken by non-admin")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("must not create key file on name conflict")
	}
}
