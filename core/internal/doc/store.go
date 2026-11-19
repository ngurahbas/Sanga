package doc

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/ngurahbas/Sanga/core/internal/storeutil"
)

type Store struct {
	db *sql.DB
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type ListOptions struct {
	Limit      int
	Offset     int
	Tag        string
	OwnerID    string
	Visibility string
}

func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
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

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func (s *Store) Create(ctx context.Context, ownerID, title, body, visibility string, tags, sharedWith []string) (*Doc, error) {
	title = strings.TrimSpace(title)
	if err := ValidateTitle(title); err != nil {
		return nil, err
	}
	if err := ValidateBody(body); err != nil {
		return nil, err
	}
	visibility = DefaultVisibility(visibility)
	if err := ValidateVisibility(visibility); err != nil {
		return nil, err
	}
	if len(tags) > MaxTags {
		return nil, ErrInvalidTag
	}
	tags = NormalizeTags(tags)
	if err := ValidateTags(tags); err != nil {
		return nil, err
	}
	if len(sharedWith) > MaxShares {
		return nil, ErrTooManyShares
	}
	for _, id := range sharedWith {
		if id == ownerID {
			return nil, ErrCannotShareOwner
		}
	}
	sharedWith = dedupeIDs(sharedWith)
	if visibility != VisibilityPrivate && len(sharedWith) > 0 {
		return nil, ErrSharesRequirePrivate
	}

	id, err := storeutil.NewID()
	if err != nil {
		return nil, err
	}
	ts := storeutil.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var docCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM documents WHERE owner_id=?`, ownerID).Scan(&docCount); err != nil {
		return nil, err
	}
	if docCount >= MaxDocsPerUser {
		return nil, ErrQuotaExceeded
	}

	if len(sharedWith) > 0 {
		args := make([]any, len(sharedWith))
		for i, uid := range sharedWith {
			args[i] = uid
		}
		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE id IN (`+placeholders(len(sharedWith))+`)`, args...).Scan(&count); err != nil {
			return nil, err
		}
		if count != len(sharedWith) {
			return nil, sql.ErrNoRows
		}
	}

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
	t := storeutil.ParseTime(ts)
	return &Doc{ID: id, OwnerID: ownerID, Title: title, Body: body, Visibility: visibility, Tags: tags, SharedWith: sharedWith, CreatedAt: t, UpdatedAt: t}, nil
}

func (s *Store) ByID(ctx context.Context, id string) (*Doc, error) {
	return s.byID(ctx, s.db, id)
}

func (s *Store) byID(ctx context.Context, q queryer, id string) (*Doc, error) {
	var d Doc
	var created, updated string
	err := q.QueryRowContext(ctx,
		`SELECT id, owner_id, title, body, visibility, created_at, updated_at FROM documents WHERE id=?`, id).
		Scan(&d.ID, &d.OwnerID, &d.Title, &d.Body, &d.Visibility, &created, &updated)
	if err != nil {
		return nil, err
	}
	d.CreatedAt = storeutil.ParseTime(created)
	d.UpdatedAt = storeutil.ParseTime(updated)
	tags, err := tagsOf(ctx, q, id)
	if err != nil {
		return nil, err
	}
	d.Tags = tags
	shares, err := sharesOf(ctx, q, id)
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

	rows, err := s.db.QueryContext(ctx, q, args...)
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
		d.CreatedAt = storeutil.ParseTime(created)
		d.UpdatedAt = storeutil.ParseTime(updated)
		out = append(out, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		ids := make([]string, len(out))
		for i, d := range out {
			ids[i] = d.ID
		}
		tags, err := s.tagsFor(ctx, ids)
		if err != nil {
			return nil, err
		}
		shares, err := s.sharesFor(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, d := range out {
			d.Tags = tags[d.ID]
			d.SharedWith = shares[d.ID]
		}
	}
	if out == nil {
		out = []*Doc{}
	}
	return out, nil
}

func (s *Store) Update(ctx context.Context, id string, patch Patch) (*Doc, error) {
	sets := []string{}
	args := []any{}
	var normalizedTags []string

	if patch.Title != nil {
		title := strings.TrimSpace(*patch.Title)
		if err := ValidateTitle(title); err != nil {
			return nil, err
		}
		sets = append(sets, "title=?")
		args = append(args, title)
	}
	if patch.Body != nil {
		if err := ValidateBody(*patch.Body); err != nil {
			return nil, err
		}
		sets = append(sets, "body=?")
		args = append(args, *patch.Body)
	}
	if patch.Visibility != nil {
		if err := ValidateVisibility(*patch.Visibility); err != nil {
			return nil, err
		}
		sets = append(sets, "visibility=?")
		args = append(args, *patch.Visibility)
	}
	if patch.Tags != nil {
		if len(*patch.Tags) > MaxTags {
			return nil, ErrInvalidTag
		}
		normalizedTags = NormalizeTags(*patch.Tags)
		if err := ValidateTags(normalizedTags); err != nil {
			return nil, err
		}
	}
	if len(sets) == 0 && patch.Tags == nil {
		return s.ByID(ctx, id)
	}

	ts := storeutil.Now()
	sets = append(sets, "updated_at=?")
	args = append(args, ts, id)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE documents SET `+strings.Join(sets, ", ")+` WHERE id=?`, args...)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, sql.ErrNoRows
	}
	if patch.Tags != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM doc_tags WHERE doc_id=?`, id); err != nil {
			return nil, err
		}
		for _, t := range normalizedTags {
			if _, err := tx.ExecContext(ctx, `INSERT INTO doc_tags(doc_id, tag) VALUES(?,?)`, id, t); err != nil {
				return nil, err
			}
		}
	}
	updatedDoc, err := s.byID(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updatedDoc, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM documents WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) AddShare(ctx context.Context, docID, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var ownerID, visibility string
	if err := tx.QueryRowContext(ctx,
		`SELECT owner_id, visibility FROM documents WHERE id=?`, docID).Scan(&ownerID, &visibility); err != nil {
		return err
	}
	if visibility != VisibilityPrivate {
		return ErrSharesRequirePrivate
	}
	if ownerID == userID {
		return ErrCannotShareOwner
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=?`, userID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO doc_shares(doc_id, user_id, created_at) VALUES(?,?,?)`,
		docID, userID, storeutil.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RemoveShare(ctx context.Context, docID, userID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM doc_shares WHERE doc_id=? AND user_id=?`, docID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func tagsOf(ctx context.Context, q queryer, docID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT tag FROM doc_tags WHERE doc_id=? ORDER BY tag`, docID)
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

func sharesOf(ctx context.Context, q queryer, docID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT user_id FROM doc_shares WHERE doc_id=? ORDER BY user_id`, docID)
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

func (s *Store) tagsFor(ctx context.Context, ids []string) (map[string][]string, error) {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT doc_id, tag FROM doc_tags WHERE doc_id IN (`+placeholders(len(ids))+`) ORDER BY doc_id, tag`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, tag string
		if err := rows.Scan(&id, &tag); err != nil {
			return nil, err
		}
		out[id] = append(out[id], tag)
	}
	return out, rows.Err()
}

func (s *Store) sharesFor(ctx context.Context, ids []string) (map[string][]string, error) {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT doc_id, user_id FROM doc_shares WHERE doc_id IN (`+placeholders(len(ids))+`) ORDER BY doc_id, user_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, userID string
		if err := rows.Scan(&id, &userID); err != nil {
			return nil, err
		}
		out[id] = append(out[id], userID)
	}
	return out, rows.Err()
}

func dedupeIDs(ids []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
