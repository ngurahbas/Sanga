package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

// Store wraps user persistence queries.
type Store struct {
	DB *sql.DB
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func scanUser(s *User, row interface {
	Scan(...any) error
}) error {
	var created, updated string
	if err := row.Scan(&s.ID, &s.Username, &s.Role, &created, &updated); err != nil {
		return err
	}
	if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
		s.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, updated); err == nil {
		s.UpdatedAt = t
	}
	return nil
}

// Create inserts a user. Returns the row.
func (s *Store) Create(ctx context.Context, username, role string) (*User, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidateRole(role); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	u := &User{
		ID:       id,
		Username: NormalizeUsername(username),
		Role:     DefaultRole(role),
	}
	ts := nowUTC()
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO users(id, username, role, created_at, updated_at) VALUES(?,?,?,?,?)`,
		u.ID, u.Username, u.Role, ts, ts)
	if err != nil {
		return nil, err
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		u.CreatedAt = t
		u.UpdatedAt = t
	}
	return u, nil
}

// ByID fetches a user by id.
func (s *Store) ByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := scanUser(&u, s.DB.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, updated_at FROM users WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ByUsername fetches a user case-insensitively (SQLite NOCASE).
func (s *Store) ByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := scanUser(&u, s.DB.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, updated_at FROM users WHERE username=?`,
		NormalizeUsername(username)))
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// List returns users ordered by username, paginated.
func (s *Store) List(ctx context.Context, limit, offset int) ([]*User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, username, role, created_at, updated_at FROM users ORDER BY username LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		var u User
		if err := scanUser(&u, rows); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

// Delete hard-deletes a user; api_keys cascade via FK.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountAdmins returns the number of users with role admin.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
