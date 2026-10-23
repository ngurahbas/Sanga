package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ngurahbas/Sanga/backend/internal/auth"
	"github.com/ngurahbas/Sanga/backend/internal/db"
	"github.com/ngurahbas/Sanga/backend/internal/user"
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

	// Generated key must authenticate.
	ks := &auth.Store{DB: database}
	if _, err := ks.Authenticate(context.Background(), res.Raw); err != nil {
		t.Fatalf("authenticate generated: %v", err)
	}

	// Second run is a no-op (admin now exists), even with file present.
	res2, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Created {
		t.Fatal("expected no-op on second run")
	}
}

func TestImportExistingFile(t *testing.T) {
	// Make a valid raw key from a scratch DB.
	src, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := db.Migrate(src); err != nil {
		t.Fatal(err)
	}
	us := &user.Store{DB: src}
	u, err := us.Create(context.Background(), "tmp", "human")
	if err != nil {
		t.Fatal(err)
	}
	ks := &auth.Store{DB: src}
	issued, err := ks.Issue(context.Background(), u.ID, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}

	// Fresh DB imports that raw from file.
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

	ks2 := &auth.Store{DB: database}
	got, err := ks2.Authenticate(context.Background(), issued.Raw)
	if err != nil {
		t.Fatalf("authenticate imported: %v", err)
	}
	us2 := &user.Store{DB: database}
	root, err := us2.ByID(context.Background(), got.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if root.Role != user.RoleAdmin || root.Username != "root" {
		t.Fatalf("root = %+v", root)
	}
}

func TestNoOpWhenAdminExists(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	us := &user.Store{DB: database}
	if _, err := us.Create(context.Background(), "root", "admin"); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(t.TempDir(), "admin.key") // does not exist
	res, err := EnsureAdmin(database, keyFile, "root")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created {
		t.Fatal("expected no-op when admin exists")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("must not create key file when admin exists")
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
	us := &user.Store{DB: database}
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
