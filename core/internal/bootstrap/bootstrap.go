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

	"github.com/ngurahbas/Sanga/core/internal/auth"
	"github.com/ngurahbas/Sanga/core/internal/user"
)

type Result struct {
	Created   bool
	Imported  bool
	Recovered bool
	KeyID     string
	Raw       string
	KeyFile   string
}

func EnsureAdmin(database *sql.DB, keyFilePath, rootUsername string) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	us := user.NewStore(database)
	ks := auth.NewStore(database)

	adminCount, err := us.CountAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("count admins: %w", err)
	}

	var target *user.User
	if adminCount > 0 {
		activeKeys, err := ks.CountActiveAdminKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("count admin keys: %w", err)
		}
		if activeKeys > 0 {
			return &Result{Created: false}, nil
		}
		target, err = us.FirstAdmin(ctx)
		if err != nil {
			return nil, fmt.Errorf("find admin: %w", err)
		}
	} else {
		rootUsername = user.NormalizeUsername(rootUsername)
		if err := user.ValidateUsername(rootUsername); err != nil {
			return nil, fmt.Errorf("invalid root username: %w", err)
		}
		if existing, err := us.ByUsername(ctx, rootUsername); err == nil && existing.Role != user.RoleAdmin {
			return nil, fmt.Errorf("username %q exists as role %q: pick another SANGA_ROOT_USERNAME or promote it manually", rootUsername, existing.Role)
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("lookup root user: %w", err)
		}
	}

	raw, imported, err := obtainKeyFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	res, err := installKey(ctx, database, us, ks, target, rootUsername, raw, imported, keyFilePath)
	if err != nil {
		if recheckActive(ctx, ks) {
			return &Result{Created: false}, nil
		}
		return nil, err
	}
	res.KeyFile = keyFilePath
	res.Recovered = target != nil
	logName := rootUsername
	if target != nil {
		logName = target.Username
	}

	switch {
	case res.Recovered:
		log.Printf("bootstrap: recovered admin key id=%s user=%s", res.KeyID, logName)
	case imported:
		log.Printf("bootstrap: imported admin key id=%s user=%s", res.KeyID, logName)
	default:
		log.Printf("bootstrap: generated admin key id=%s user=%s file=%s", res.KeyID, logName, keyFilePath)
	}
	return res, nil
}

func installKey(ctx context.Context, database *sql.DB, us *user.Store, ks *auth.Store, target *user.User, rootUsername, raw string, imported bool, keyFilePath string) (*Result, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	u := target
	if u == nil {
		u, err = ensureRootUserTx(ctx, us, tx, rootUsername)
		if err != nil {
			return nil, err
		}
	}
	k, err := ks.ImportRawKeyTx(ctx, tx, u.ID, raw, "bootstrap")
	if err != nil {
		return nil, fmt.Errorf("store admin key: %w (key file retained at %s, retry startup to import)", err, keyFilePath)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	res := &Result{Created: true, Imported: imported, KeyID: k.ID}
	if !imported {
		res.Raw = raw
	}
	return res, nil
}

func ensureRootUserTx(ctx context.Context, us *user.Store, tx *sql.Tx, rootUsername string) (*user.User, error) {
	u, err := us.ByUsernameTx(ctx, tx, rootUsername)
	if err == nil {
		if u.Role != user.RoleAdmin {
			return nil, fmt.Errorf("username %q exists as role %q: pick another SANGA_ROOT_USERNAME or promote it manually", rootUsername, u.Role)
		}
		return u, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	u, err = us.CreateTx(ctx, tx, rootUsername, user.RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("create root user: %w", err)
	}
	return u, nil
}

func obtainKeyFile(path string) (string, bool, error) {
	raw, err := readKeyFile(path)
	if err == nil {
		return raw, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("read admin key file: %w", err)
	}

	_, _, raw, err = auth.GenerateRaw()
	if err != nil {
		return "", false, fmt.Errorf("generate admin key: %w", err)
	}
	if err := writeKeyFileExclusive(path, raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			raw, err := readKeyFile(path)
			if err != nil {
				return "", false, fmt.Errorf("read admin key file: %w", err)
			}
			return raw, true, nil
		}
		return "", false, fmt.Errorf("write admin key file: %w", err)
	}
	return raw, false, nil
}

func recheckActive(ctx context.Context, ks *auth.Store) bool {
	n, err := ks.CountActiveAdminKeys(ctx)
	return err == nil && n > 0
}

func readKeyFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: admin key file %s is accessible by group or others", path)
	}
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
	dirPath := filepath.Dir(path)
	if dirPath != "." && dirPath != "" {
		if err := os.MkdirAll(dirPath, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(raw + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
