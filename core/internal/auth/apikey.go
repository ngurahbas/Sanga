package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ngurahbas/Sanga/core/internal/storeutil"
)

const (
	MaxActiveKeys = 10
	MaxKeyName    = 100
)

var (
	ErrInvalidKey        = errors.New("invalid api key")
	ErrInvalidKeyFormat  = errors.New("invalid api key format")
	ErrKeyRevoked        = errors.New("api key revoked")
	ErrKeyNotFound       = errors.New("api key not found")
	ErrKeyAlreadyRevoked = errors.New("api key already revoked")
	ErrKeyLimit          = errors.New("key limit reached")
	ErrInvalidKeyName    = errors.New("key name must be at most 100 chars")
	ErrLastAdminKey      = errors.New("cannot revoke the last active key of the last admin")
)

type Key struct {
	ID         string
	UserID     string
	KeyPrefix  string
	Name       string
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

type IssuedKey struct {
	Key
	Raw string
}

type Store struct {
	db *sql.DB
}

func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
}

func randB64(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func parseTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := storeutil.ParseTime(s.String)
	if t.IsZero() {
		return nil
	}
	return &t
}

func GenerateRaw() (id, secret, raw string, err error) {
	id, err = randB64(9)
	if err != nil {
		return "", "", "", err
	}
	secret, err = randB64(32)
	if err != nil {
		return "", "", "", err
	}
	return id, secret, id + "." + secret, nil
}

func validateKeyName(name string) error {
	if len([]rune(name)) > MaxKeyName {
		return ErrInvalidKeyName
	}
	return nil
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func issue(ctx context.Context, db execer, userID, name string) (*IssuedKey, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, errors.New("user id required")
	}
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	id, secret, raw, err := GenerateRaw()
	if err != nil {
		return nil, err
	}
	prefix := secret[:8]
	now := storeutil.Now()

	res, err := db.ExecContext(ctx,
		`INSERT INTO api_keys(id, user_id, key_hash, key_prefix, name, created_at)
		 SELECT ?,?,?,?,?,?
		 WHERE (SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked_at IS NULL) < ?`,
		id, userID, hashSecret(secret), prefix, name, now, userID, MaxActiveKeys)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrKeyLimit
	}
	return &IssuedKey{
		Key: Key{ID: id, UserID: userID, KeyPrefix: prefix, Name: name, CreatedAt: storeutil.ParseTime(now)},
		Raw: raw,
	}, nil
}

func (s *Store) Issue(ctx context.Context, userID, name string) (*IssuedKey, error) {
	return issue(ctx, s.db, userID, name)
}

func ValidateRaw(raw string) (id, secret string, err error) {
	raw = strings.TrimSpace(raw)
	id, secret, ok := strings.Cut(raw, ".")
	if !ok || id == "" || secret == "" {
		return "", "", ErrInvalidKeyFormat
	}
	if len(id) < 8 {
		return "", "", ErrInvalidKeyFormat
	}
	if len(secret) < 32 {
		return "", "", ErrInvalidKeyFormat
	}
	for _, c := range id + secret {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", "", ErrInvalidKeyFormat
		}
	}
	return id, secret, nil
}

func importRawKey(ctx context.Context, db execer, userID, raw, name string) (*Key, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, errors.New("user id required")
	}
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	id, secret, err := ValidateRaw(raw)
	if err != nil {
		return nil, err
	}
	prefix := secret[:8]
	now := storeutil.Now()
	_, err = db.ExecContext(ctx,
		`INSERT INTO api_keys(id, user_id, key_hash, key_prefix, name, created_at) VALUES(?,?,?,?,?,?)`,
		id, userID, hashSecret(secret), prefix, name, now)
	if err != nil {
		return nil, err
	}
	return &Key{ID: id, UserID: userID, KeyPrefix: prefix, Name: name, CreatedAt: storeutil.ParseTime(now)}, nil
}

func (s *Store) ImportRawKey(ctx context.Context, userID, raw, name string) (*Key, error) {
	return importRawKey(ctx, s.db, userID, raw, name)
}

func (s *Store) ImportRawKeyTx(ctx context.Context, tx *sql.Tx, userID, raw, name string) (*Key, error) {
	return importRawKey(ctx, tx, userID, raw, name)
}

func (s *Store) Authenticate(ctx context.Context, raw string) (*Key, error) {
	id, secret, err := ValidateRaw(raw)
	if err != nil {
		return nil, ErrInvalidKey
	}
	var k Key
	var revoked, lastUsed, created sql.NullString
	var userID, prefix, name string
	var storedHash []byte
	err = s.db.QueryRowContext(ctx,
		`SELECT id, user_id, key_hash, key_prefix, name, revoked_at, last_used_at, created_at
		 FROM api_keys WHERE id=?`, id).
		Scan(&k.ID, &userID, &storedHash, &prefix, &name, &revoked, &lastUsed, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidKey
	}
	if err != nil {
		return nil, fmt.Errorf("lookup api key: %w", err)
	}
	if subtle.ConstantTimeCompare(storedHash, hashSecret(secret)) != 1 {
		return nil, ErrInvalidKey
	}
	k.UserID = userID
	k.KeyPrefix = prefix
	k.Name = name
	k.RevokedAt = parseTime(revoked)
	k.LastUsedAt = parseTime(lastUsed)
	if t := storeutil.ParseTime(created.String); !t.IsZero() {
		k.CreatedAt = t
	}
	if k.RevokedAt != nil {
		return nil, ErrKeyRevoked
	}

	staleBefore := storeutil.FormatTime(time.Now().Add(-time.Minute))
	_, _ = s.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at=?
		 WHERE id=? AND (last_used_at IS NULL OR last_used_at < ?)`,
		storeutil.Now(), id, staleBefore)
	return &k, nil
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var userID string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT user_id, revoked_at FROM api_keys WHERE id=?`, id).Scan(&userID, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrKeyNotFound
		}
		return err
	}
	if revoked.Valid && revoked.String != "" {
		return ErrKeyAlreadyRevoked
	}

	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, userID).Scan(&role); err != nil {
		return err
	}
	if role == "admin" {
		var admins, active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&admins); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked_at IS NULL`, userID).Scan(&active); err != nil {
			return err
		}
		if admins <= 1 && active <= 1 {
			return ErrLastAdminKey
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		storeutil.Now(), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) OwnerOf(ctx context.Context, id string) (string, error) {
	var userID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM api_keys WHERE id=?`, id).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrKeyNotFound
		}
		return "", err
	}
	return userID, nil
}

func (s *Store) ByID(ctx context.Context, id string) (*Key, error) {
	var k Key
	var revoked, lastUsed, created sql.NullString
	var prefix, name string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, key_prefix, name, revoked_at, last_used_at, created_at
		 FROM api_keys WHERE id=?`, id).
		Scan(&k.ID, &k.UserID, &prefix, &name, &revoked, &lastUsed, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	k.KeyPrefix = prefix
	k.Name = name
	k.RevokedAt = parseTime(revoked)
	k.LastUsedAt = parseTime(lastUsed)
	k.CreatedAt = storeutil.ParseTime(created.String)
	return &k, nil
}

func (s *Store) ListByUser(ctx context.Context, userID string) ([]*Key, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, key_prefix, name, revoked_at, last_used_at, created_at
		 FROM api_keys WHERE user_id=? ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Key
	for rows.Next() {
		var k Key
		var revoked, lastUsed, created sql.NullString
		var prefix, name string
		if err := rows.Scan(&k.ID, &k.UserID, &prefix, &name, &revoked, &lastUsed, &created); err != nil {
			return nil, err
		}
		k.KeyPrefix = prefix
		k.Name = name
		k.RevokedAt = parseTime(revoked)
		k.LastUsedAt = parseTime(lastUsed)
		k.CreatedAt = storeutil.ParseTime(created.String)
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (s *Store) ActiveCount(ctx context.Context, userID string) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked_at IS NULL`, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) CountActiveAdminKeys(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_keys k JOIN users u ON u.id=k.user_id
		 WHERE u.role='admin' AND k.revoked_at IS NULL`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) Rotate(ctx context.Context, userID, oldID, name string) (*IssuedKey, error) {
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var owner string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT user_id, revoked_at FROM api_keys WHERE id=?`, oldID).Scan(&owner, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	if owner != userID {
		return nil, ErrKeyNotFound
	}
	if revoked.Valid && revoked.String != "" {
		return nil, ErrKeyAlreadyRevoked
	}

	id, secret, raw, err := GenerateRaw()
	if err != nil {
		return nil, err
	}
	now := storeutil.Now()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO api_keys(id, user_id, key_hash, key_prefix, name, created_at) VALUES(?,?,?,?,?,?)`,
		id, userID, hashSecret(secret), secret[:8], name, now); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now, oldID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrKeyAlreadyRevoked
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &IssuedKey{
		Key: Key{ID: id, UserID: userID, KeyPrefix: secret[:8], Name: name, CreatedAt: storeutil.ParseTime(now)},
		Raw: raw,
	}, nil
}

func FromRequest(apiKeyHeader, authHeader string) string {
	if apiKeyHeader != "" {
		return strings.TrimSpace(apiKeyHeader)
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
