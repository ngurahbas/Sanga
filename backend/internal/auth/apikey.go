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

// Key record mirrors api_keys row (without raw secret).
type Key struct {
	ID         string
	UserID     string
	KeyPrefix  string
	Name       string
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// IssuedKey is returned once at creation: Raw is the only time the secret is visible.
type IssuedKey struct {
	Key
	Raw string // "<id>.<secret>" — store nowhere, show once
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

// Issue creates a key for userID. Returns raw key once.
// Raw format is "<id>.<secret>" where both parts are base64 RawURLEncoding
// (alphabet A-Za-z0-9-_), so "." never appears inside either part and
// strings.Cut on "." is safe.
func (s *Store) Issue(ctx context.Context, userID, name string) (*IssuedKey, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, errors.New("user id required")
	}
	id, err := randB64(9) // 12 chars
	if err != nil {
		return nil, err
	}
	secret, err := randB64(32) // 43 chars, ~256-bit
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
		Raw: id + "." + secret,
	}, nil
}

// Authenticate verifies "<id>.<secret>", checks revocation, bumps last_used_at.
// Returns key + user role lookup is left to caller via user Store.
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

// Revoke sets revoked_at. Returns error if the key is not found or already revoked.
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

// FromRequest extracts key from X-API-Key or Authorization: Bearer (scheme case-insensitive).
func FromRequest(apiKeyHeader, authHeader string) string {
	if apiKeyHeader != "" {
		return strings.TrimSpace(apiKeyHeader)
	}
	// Scheme per RFC 7235 is case-insensitive; value may be "Bearer", "bearer", etc.
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
