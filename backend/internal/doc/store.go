package doc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"
)

type Store struct {
	DB *sql.DB
}

type ListOptions struct {
	Limit      int
	Offset     int
	Tag        string
	OwnerID    string
	Visibility string
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

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func CanRead(d *Doc, callerID string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	if d.Visibility == VisibilityPublic {
		return true
	}
	if callerID == d.OwnerID {
		return true
	}
	return contains(d.SharedWith, callerID)
}

func CanWrite(d *Doc, callerID string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	return callerID == d.OwnerID
}

func (s *Store) Create(ctx context.Context, ownerID, title, body, visibility string, tags, sharedWith []string) (*Doc, error) {
	title = trimTitle(title)
	if err := ValidateTitle(title); err != nil {
		return nil, err
	}
	if err := ValidateBody(body); err != nil {
		return nil, err
	}
	if err := ValidateVisibility(visibility); err != nil {
		return nil, err
	}
	tags = NormalizeTags(tags)
	if err := ValidateTags(tags); err != nil {
		return nil, err
	}
	visibility = DefaultVisibility(visibility)
	sharedWith = dedupeIDs(sharedWith, ownerID)

	id, err := newID()
	if err != nil {
		return nil, err
	}
	for _, uid := range sharedWith {
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=?`, uid).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, sql.ErrNoRows
		}
	}

	ts := nowUTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO documents(id, owner_id, title, body, visibility, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
		id, ownerID, title, body, visibility, ts, ts); err != nil {
		return nil, err
	}
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT INTO doc_tags(doc_id, tag) VALUES(?,?)`, id, t); err != nil {
			return nil, err
		}
	}
	for _, uid := range sharedWith {
		if _, err := tx.ExecContext(ctx, `INSERT INTO doc_shares(doc_id, user_id, created_at) VALUES(?,?,?)`, id, uid, ts); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	t := parseTime(ts)
	return &Doc{ID: id, OwnerID: ownerID, Title: title, Body: body, Visibility: visibility, Tags: tags, SharedWith: sharedWith, CreatedAt: t, UpdatedAt: t}, nil
}

func (s *Store) ByID(ctx context.Context, id string) (*Doc, error) {
	var d Doc
	var created, updated string
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, owner_id, title, body, visibility, created_at, updated_at FROM documents WHERE id=?`, id).
		Scan(&d.ID, &d.OwnerID, &d.Title, &d.Body, &d.Visibility, &created, &updated)
	if err != nil {
		return nil, err
	}
	d.CreatedAt = parseTime(created)
	d.UpdatedAt = parseTime(updated)
	tags, err := s.tagsOf(ctx, id)
	if err != nil {
		return nil, err
	}
	d.Tags = tags
	shares, err := s.sharesOf(ctx, id)
	if err != nil {
		return nil, err
	}
	d.SharedWith = shares
	return &d, nil
}

func (s *Store) ListReadable(ctx context.Context, callerID string, isAdmin bool, opts ListOptions) ([]*Doc, error) {
	limit := opts.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}
	q := `SELECT d.id, d.owner_id, d.title, d.body, d.visibility, d.created_at, d.updated_at
		FROM documents d WHERE 1=1`
	args := []any{}
	if !isAdmin {
		q += ` AND (d.visibility='public' OR d.owner_id=? OR EXISTS(SELECT 1 FROM doc_shares s WHERE s.doc_id=d.id AND s.user_id=?))`
		args = append(args, callerID, callerID)
	}
	if opts.OwnerID != "" {
		q += ` AND d.owner_id=?`
		args = append(args, opts.OwnerID)
	}
	if opts.Visibility == VisibilityPublic || opts.Visibility == VisibilityPrivate {
		q += ` AND d.visibility=?`
		args = append(args, opts.Visibility)
	}
	if opts.Tag != "" {
		q += ` AND EXISTS(SELECT 1 FROM doc_tags t WHERE t.doc_id=d.id AND t.tag=?)`
		args = append(args, NormalizeTag(opts.Tag))
	}
	q += ` ORDER BY d.created_at DESC, d.id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Doc
	for rows.Next() {
		var d Doc
		var created, updated string
		if err := rows.Scan(&d.ID, &d.OwnerID, &d.Title, &d.Body, &d.Visibility, &created, &updated); err != nil {
			return nil, err
		}
		d.CreatedAt = parseTime(created)
		d.UpdatedAt = parseTime(updated)
		out = append(out, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, d := range out {
		tags, err := s.tagsOf(ctx, d.ID)
		if err != nil {
			return nil, err
		}
		d.Tags = tags
		shares, err := s.sharesOf(ctx, d.ID)
		if err != nil {
			return nil, err
		}
		d.SharedWith = shares
	}
	if out == nil {
		out = []*Doc{}
	}
	return out, nil
}

func (s *Store) Update(ctx context.Context, id, title, body, visibility string, tags []string) (*Doc, error) {
	title = trimTitle(title)
	if err := ValidateTitle(title); err != nil {
		return nil, err
	}
	if err := ValidateBody(body); err != nil {
		return nil, err
	}
	if err := ValidateVisibility(visibility); err != nil {
		return nil, err
	}
	tags = NormalizeTags(tags)
	if err := ValidateTags(tags); err != nil {
		return nil, err
	}
	visibility = DefaultVisibility(visibility)

	ts := nowUTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE documents SET title=?, body=?, visibility=?, updated_at=? WHERE id=?`,
		title, body, visibility, ts, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM doc_tags WHERE doc_id=?`, id); err != nil {
		return nil, err
	}
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT INTO doc_tags(doc_id, tag) VALUES(?,?)`, id, t); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.ByID(ctx, id)
}

func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM documents WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) AddShare(ctx context.Context, docID, userID string) error {
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=?`, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT OR IGNORE INTO doc_shares(doc_id, user_id, created_at) VALUES(?,?,?)`,
		docID, userID, nowUTC()); err != nil {
		return err
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM documents WHERE id=?`, docID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RemoveShare(ctx context.Context, docID, userID string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM doc_shares WHERE doc_id=? AND user_id=?`, docID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) tagsOf(ctx context.Context, docID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT tag FROM doc_tags WHERE doc_id=? ORDER BY tag`, docID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) sharesOf(ctx context.Context, docID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT user_id FROM doc_shares WHERE doc_id=? ORDER BY user_id`, docID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func trimTitle(s string) string {
	if len(s) > MaxTitleRunes*4+16 {
	}
	return strings.TrimSpace(s)
}

func dedupeIDs(ids []string, exclude string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, id := range ids {
		if id == "" || id == exclude {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
