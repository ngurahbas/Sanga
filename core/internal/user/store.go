package user

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ngurahbas/Sanga/core/internal/storeutil"
)

var ErrLastAdmin = errors.New("cannot delete the last admin")

type Store struct {
	db *sql.DB
}

func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
}

func scanUser(s *User, row interface {
	Scan(...any) error
}) error {
	var created, updated string
	if err := row.Scan(&s.ID, &s.Username, &s.Role, &created, &updated); err != nil {
		return err
	}
	s.CreatedAt = storeutil.ParseTime(created)
	s.UpdatedAt = storeutil.ParseTime(updated)
	return nil
}

func create(ctx context.Context, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, username, role string) (*User, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidateRole(role); err != nil {
		return nil, err
	}
	id, err := storeutil.NewID()
	if err != nil {
		return nil, err
	}
	u := &User{
		ID:       id,
		Username: NormalizeUsername(username),
		Role:     DefaultRole(role),
	}
	ts := storeutil.Now()
	_, err = db.ExecContext(ctx,
		`INSERT INTO users(id, username, role, created_at, updated_at) VALUES(?,?,?,?,?)`,
		u.ID, u.Username, u.Role, ts, ts)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = storeutil.ParseTime(ts)
	u.UpdatedAt = u.CreatedAt
	return u, nil
}

func (s *Store) Create(ctx context.Context, username, role string) (*User, error) {
	return create(ctx, s.db, username, role)
}

func (s *Store) CreateTx(ctx context.Context, tx *sql.Tx, username, role string) (*User, error) {
	return create(ctx, tx, username, role)
}

func (s *Store) ByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := scanUser(&u, s.db.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, updated_at FROM users WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) ByUsername(ctx context.Context, username string) (*User, error) {
	return byUsername(ctx, s.db, username)
}

func (s *Store) ByUsernameTx(ctx context.Context, tx *sql.Tx, username string) (*User, error) {
	return byUsername(ctx, tx, username)
}

func byUsername(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, username string) (*User, error) {
	var u User
	err := scanUser(&u, db.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, updated_at FROM users WHERE username=?`,
		NormalizeUsername(username)))
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) List(ctx context.Context, limit, offset int) ([]*User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx,
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

func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM users
		 WHERE id=?
		   AND (role <> 'admin' OR (SELECT COUNT(*) FROM users WHERE role='admin') > 1)`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=?`, id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return sql.ErrNoRows
	}
	return ErrLastAdmin
}

func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) FirstAdmin(ctx context.Context) (*User, error) {
	var u User
	err := scanUser(&u, s.db.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, updated_at
		 FROM users WHERE role='admin' ORDER BY created_at, id LIMIT 1`))
	if err != nil {
		return nil, err
	}
	return &u, nil
}
