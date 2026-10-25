package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ngurahbas/Sanga/backend/internal/auth"
	"github.com/ngurahbas/Sanga/backend/internal/user"
)

type Result struct {
	Created  bool
	Imported bool
	KeyID    string
	Raw      string
	KeyFile  string
}

func EnsureAdmin(database *sql.DB, keyFilePath, rootUsername string) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var adminCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&adminCount); err != nil {
		return nil, fmt.Errorf("count admins: %w", err)
	}
	if adminCount > 0 {
		return &Result{Created: false}, nil
	}

	rootUsername = user.NormalizeUsername(rootUsername)
	if err := user.ValidateUsername(rootUsername); err != nil {
		return nil, fmt.Errorf("invalid root username: %w", err)
	}

	us := &user.Store{DB: database}
	ks := &auth.Store{DB: database}

	if raw, err := readKeyFile(keyFilePath); err == nil {
		u, created, err := ensureRootUser(ctx, us, rootUsername)
		if err != nil {
			return nil, err
		}
		k, err := ks.ImportRawKey(ctx, u.ID, raw, "bootstrap")
		if err != nil {
			if created {
				deleteUser(ctx, database, u.ID)
			}
			if recheck(ctx, database) {
				return &Result{Created: false}, nil
			}
			return nil, fmt.Errorf("import admin key: %w", err)
		}
		log.Printf("bootstrap: imported admin key id=%s prefix=%s user=%s", k.ID, k.KeyPrefix, rootUsername)
		return &Result{Created: true, Imported: true, KeyID: k.ID, KeyFile: keyFilePath}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read admin key file: %w", err)
	}

	if existing, err := us.ByUsername(ctx, rootUsername); err == nil && existing.Role != user.RoleAdmin {
		return nil, fmt.Errorf("username %q exists as role %q: pick another SANGA_ROOT_USERNAME or promote it manually", rootUsername, existing.Role)
	}

	_, _, raw, err := auth.GenerateRaw()
	if err != nil {
		return nil, fmt.Errorf("generate admin key: %w", err)
	}
	if _, _, err := auth.ValidateRaw(raw); err != nil {
		return nil, err
	}
	if err := writeKeyFileExclusive(keyFilePath, raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			if raw2, err2 := readKeyFile(keyFilePath); err2 == nil {
				u, created, err := ensureRootUser(ctx, us, rootUsername)
				if err != nil {
					return nil, err
				}
				k, err := ks.ImportRawKey(ctx, u.ID, raw2, "bootstrap")
				if err != nil {
					if created {
						deleteUser(ctx, database, u.ID)
					}
					if recheck(ctx, database) {
						return &Result{Created: false}, nil
					}
					return nil, fmt.Errorf("import admin key: %w", err)
				}
				log.Printf("bootstrap: imported admin key id=%s user=%s", k.ID, rootUsername)
				return &Result{Created: true, Imported: true, KeyID: k.ID, KeyFile: keyFilePath}, nil
			}
		}
		if recheck(ctx, database) {
			return &Result{Created: false}, nil
		}
		return nil, fmt.Errorf("write admin key file: %w", err)
	}

	u, created, err := ensureRootUser(ctx, us, rootUsername)
	if err != nil {
		return nil, err
	}
	k, err := ks.ImportRawKey(ctx, u.ID, raw, "bootstrap")
	if err != nil {
		if created {
			deleteUser(ctx, database, u.ID)
		}
		return nil, fmt.Errorf("store admin key: %w (key file retained at %s, retry startup to import)", err, keyFilePath)
	}
	log.Printf("bootstrap: generated admin key id=%s user=%s file=%s", k.ID, rootUsername, keyFilePath)
	return &Result{Created: true, Imported: false, KeyID: k.ID, Raw: raw, KeyFile: keyFilePath}, nil
}

func ensureRootUser(ctx context.Context, us *user.Store, rootUsername string) (*user.User, bool, error) {
	if u, err := us.ByUsername(ctx, rootUsername); err == nil {
		if u.Role != user.RoleAdmin {
			return nil, false, fmt.Errorf("username %q exists as role %q: pick another SANGA_ROOT_USERNAME or promote it manually", rootUsername, u.Role)
		}
		return u, false, nil
	}
	u, err := us.Create(ctx, rootUsername, user.RoleAdmin)
	if err != nil {
		if existing, err2 := us.ByUsername(ctx, rootUsername); err2 == nil {
			if existing.Role != user.RoleAdmin {
				return nil, false, fmt.Errorf("username %q exists as role %q: pick another SANGA_ROOT_USERNAME or promote it manually", rootUsername, existing.Role)
			}
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("create root user: %w", err)
	}
	return u, true, nil
}

func deleteUser(ctx context.Context, database *sql.DB, id string) {
	_, _ = database.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
}

func recheck(ctx context.Context, database *sql.DB) bool {
	var n int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func readKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(string(b))
	if raw == "" {
		return "", errors.New("admin key file is empty")
	}
	if _, _, err := auth.ValidateRaw(raw); err != nil {
		return "", err
	}
	return raw, nil
}

func writeKeyFileExclusive(path, raw string) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(raw + "\n"); err != nil {
		return err
	}
	return f.Sync()
}
