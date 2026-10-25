package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
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
	DB *sql.DB
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
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
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

func (s *Store) Issue(ctx context.Context, userID, name string) (*IssuedKey, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, errors.New("user id required")
	}
	id, secret, raw, err := GenerateRaw()
	if err != nil {
		return nil, err
	}
	prefix := secret[:8]
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO api_keys(id, user_id, key_hash, key_prefix, name, created_at) VALUES(?,?,?,?,?,?)`,
		id, userID, hashSecret(secret), prefix, name, now)
	if err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339Nano, now)
	return &IssuedKey{
		Key: Key{ID: id, UserID: userID, KeyPrefix: prefix, Name: name, CreatedAt: t},
		Raw: raw,
	}, nil
}

func ValidateRaw(raw string) (id, secret string, err error) {
	raw = strings.TrimSpace(raw)
	id, secret, ok := strings.Cut(raw, ".")
	if !ok || id == "" || secret == "" {
		return "", "", errors.New("invalid api key format")
	}
	if len(id) < 8 {
		return "", "", errors.New("invalid api key id")
	}
	if len(secret) < 32 {
		return "", "", errors.New("api key secret too short")
	}
	for _, c := range id + secret {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", "", errors.New("invalid api key characters")
		}
	}
	return id, secret, nil
}

func (s *Store) ImportRawKey(ctx context.Context, userID, raw, name string) (*Key, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, errors.New("user id required")
	}
	id, secret, err := ValidateRaw(raw)
	if err != nil {
		return nil, err
	}
	prefix := secret[:8]
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO api_keys(id, user_id, key_hash, key_prefix, name, created_at) VALUES(?,?,?,?,?,?)`,
		id, userID, hashSecret(secret), prefix, name, now)
	if err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339Nano, now)
	return &Key{ID: id, UserID: userID, KeyPrefix: prefix, Name: name, CreatedAt: t}, nil
}

func (s *Store) Authenticate(ctx context.Context, raw string) (*Key, error) {
	id, secret, ok := strings.Cut(strings.TrimSpace(raw), ".")
	if !ok || id == "" || secret == "" {
		return nil, errors.New("invalid api key format")
	}
	var k Key
	var revoked, lastUsed, created sql.NullString
	var userID, prefix, name string
	var storedHash []byte
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, key_hash, key_prefix, name, revoked_at, last_used_at, created_at
		 FROM api_keys WHERE id=?`, id).
		Scan(&k.ID, &userID, &storedHash, &prefix, &name, &revoked, &lastUsed, &created)
	if err != nil {
		return nil, errors.New("invalid api key")
	}
	if subtle.ConstantTimeCompare(storedHash, hashSecret(secret)) != 1 {
		return nil, errors.New("invalid api key")
	}
	k.UserID = userID
	k.KeyPrefix = prefix
	k.Name = name
	k.RevokedAt = parseTime(revoked)
	k.LastUsedAt = parseTime(lastUsed)
	if t, err := time.Parse(time.RFC3339Nano, created.String); err == nil {
		k.CreatedAt = t
	}
	if k.RevokedAt != nil {
		return nil, errors.New("api key revoked")
	}

	_, _ = s.DB.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	return &k, nil
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("api key not found or already revoked")
	}
	return nil
}

func (s *Store) OwnerOf(ctx context.Context, id string) (string, error) {
	var userID string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT user_id FROM api_keys WHERE id=?`, id).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return userID, nil
}

func (s *Store) ListByUser(ctx context.Context, userID string) ([]*Key, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, user_id, key_prefix, name, revoked_at, last_used_at, created_at
		 FROM api_keys WHERE user_id=? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Key
	for rows.Next() {
		var k Key
		var revoked, lastUsed, created sql.NullString
		var owner, prefix, name string
		if err := rows.Scan(&k.ID, &owner, &prefix, &name, &revoked, &lastUsed, &created); err != nil {
			return nil, err
		}
		k.UserID = owner
		k.KeyPrefix = prefix
		k.Name = name
		k.RevokedAt = parseTime(revoked)
		k.LastUsedAt = parseTime(lastUsed)
		if t, err := time.Parse(time.RFC3339Nano, created.String); err == nil {
			k.CreatedAt = t
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (s *Store) ActiveCount(ctx context.Context, userID string) (int, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked_at IS NULL`, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) Rotate(ctx context.Context, userID, oldID, name string) (*IssuedKey, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var owner string
	var revoked sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT user_id, revoked_at FROM api_keys WHERE id=?`, oldID).Scan(&owner, &revoked); err != nil {
		return nil, errors.New("api key not found")
	}
	if owner != userID {
		return nil, errors.New("api key not found")
	}
	if revoked.Valid && revoked.String != "" {
		return nil, errors.New("api key already revoked")
	}

	id, secret, raw, err := GenerateRaw()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO api_keys(id, user_id, key_hash, key_prefix, name, created_at) VALUES(?,?,?,?,?,?)`,
		id, userID, hashSecret(secret), secret[:8], name, now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now, oldID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339Nano, now)
	return &IssuedKey{
		Key: Key{ID: id, UserID: userID, KeyPrefix: secret[:8], Name: name, CreatedAt: t},
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
