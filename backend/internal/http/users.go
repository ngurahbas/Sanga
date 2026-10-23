package http

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ngurahbas/Sanga/backend/internal/auth"
	"github.com/ngurahbas/Sanga/backend/internal/user"
)

// MaxActiveKeys caps active (non-revoked) keys per user.
const MaxActiveKeys = 10

// UsersHandler serves /users endpoints. Mount via MountUsers.
type UsersHandler struct {
	users *user.Store
	keys  *auth.Store
}

// MountUsers wires /users routes onto mux. All require auth; /health stays public.
func MountUsers(mux *http.ServeMux, database *sql.DB) {
	h := &UsersHandler{users: &user.Store{DB: database}, keys: &auth.Store{DB: database}}
	authed := func(pattern string, fn http.HandlerFunc) {
		mux.Handle(pattern, auth.WithAuth(h.keys, h.users, fn))
	}
	authed("POST /users", h.createUser)
	authed("GET /users", h.listUsers)
	authed("GET /users/me", h.me)
	authed("GET /users/{id}", h.getUser)
	authed("DELETE /users/{id}", h.deleteUser)
	authed("POST /users/{id}/keys", h.issueKey)
	authed("GET /users/{id}/keys", h.listKeys)
	authed("POST /users/{id}/keys/{keyID}/rotate", h.rotateKey)
	authed("DELETE /users/{id}/keys/{keyID}", h.revokeKey)
}

type userJSON struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type keyJSON struct {
	ID         string  `json:"id"`
	KeyPrefix  string  `json:"key_prefix"`
	Name       string  `json:"name"`
	RevokedAt  *string `json:"revoked_at"`
	LastUsedAt *string `json:"last_used_at"`
	CreatedAt  string  `json:"created_at"`
}

func toUserJSON(u *user.User) userJSON {
	return userJSON{u.ID, u.Username, u.Role,
		u.CreatedAt.UTC().Format(time.RFC3339Nano),
		u.UpdatedAt.UTC().Format(time.RFC3339Nano)}
}

func strptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func toKeyJSON(k *auth.Key) keyJSON {
	return keyJSON{k.ID, k.KeyPrefix, k.Name,
		strptr(k.RevokedAt), strptr(k.LastUsedAt),
		k.CreatedAt.UTC().Format(time.RFC3339Nano)}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if err == io.EOF {
			return true // empty body: leave v at zero value
		}
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func caller(r *http.Request) (*user.User, bool) {
	return auth.UserFromContext(r.Context())
}

// selfOrAdmin: admins act on anyone; others only on themselves.
func selfOrAdmin(c *user.User, targetID string) bool {
	if auth.RequireRole(c, user.RoleAdmin) {
		return true
	}
	return c.ID == targetID
}

func isDuplicate(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// POST /users — admin only.
func (h *UsersHandler) createUser(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok || !auth.RequireRole(c, user.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	u, err := h.users.Create(r.Context(), body.Username, body.Role)
	if err != nil {
		switch {
		case isDuplicate(err):
			writeErr(w, http.StatusConflict, "username taken")
		case errors.Is(err, user.ErrInvalidUsername), errors.Is(err, user.ErrInvalidRole):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "create failed")
		}
		return
	}
	w.Header().Set("Location", "/users/"+u.ID)
	writeJSON(w, http.StatusCreated, toUserJSON(u))
}

// GET /users — any authed user.
func (h *UsersHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := caller(r); !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	users, err := h.users.List(r.Context(), limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /users/me — own profile + active key count.
func (h *UsersHandler) me(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	n, err := h.keys.ActiveCount(r.Context(), c.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserJSON(c), "active_keys": n})
}

// GET /users/{id} — any authed user.
func (h *UsersHandler) getUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := caller(r); !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	u, err := h.users.ByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserJSON(u))
}

// DELETE /users/{id} — admin only, hard delete (keys cascade). Refuses last admin.
func (h *UsersHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok || !auth.RequireRole(c, user.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	id := r.PathValue("id")
	target, err := h.users.ByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Role == user.RoleAdmin {
		n, err := h.users.CountAdmins(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		if n <= 1 {
			writeErr(w, http.StatusConflict, "cannot delete the last admin")
			return
		}
	}
	if err := h.users.Delete(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /users/{id}/keys — admin any, self own. Cap MaxActiveKeys.
func (h *UsersHandler) issueKey(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if !selfOrAdmin(c, id) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	n, err := h.keys.ActiveCount(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if n >= MaxActiveKeys {
		writeErr(w, http.StatusConflict, "key limit reached")
		return
	}
	issued, err := h.keys.Issue(r.Context(), id, body.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "issue failed")
		return
	}
	out := toKeyJSON(&issued.Key)
	writeJSON(w, http.StatusCreated, map[string]any{"key": out, "raw": issued.Raw})
}

// GET /users/{id}/keys — any authed user. Metadata only.
func (h *UsersHandler) listKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := caller(r); !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	keys, err := h.keys.ListByUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]keyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, toKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /users/{id}/keys/{keyID}/rotate — admin any, self own.
func (h *UsersHandler) rotateKey(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	keyID := r.PathValue("keyID")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if !selfOrAdmin(c, id) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	owner, err := h.keys.OwnerOf(r.Context(), keyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if owner != id {
		writeErr(w, http.StatusNotFound, "api key not found")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	// Name is optional: an empty body keeps the old name.
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" {
		if keys, err := h.keys.ListByUser(r.Context(), id); err == nil {
			for _, k := range keys {
				if k.ID == keyID {
					body.Name = k.Name
					break
				}
			}
		}
	}
	n, err := h.keys.ActiveCount(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if n > MaxActiveKeys {
		// Over cap (should not happen): rotation is net-zero, so at-cap rotates fine.
		writeErr(w, http.StatusConflict, "key limit reached")
		return
	}
	rotated, err := h.keys.Rotate(r.Context(), id, keyID, body.Name)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			writeErr(w, http.StatusNotFound, "api key not found")
		case strings.Contains(msg, "already revoked"):
			writeErr(w, http.StatusConflict, "api key already revoked")
		default:
			writeErr(w, http.StatusInternalServerError, "rotate failed")
		}
		return
	}
	out := toKeyJSON(&rotated.Key)
	writeJSON(w, http.StatusCreated, map[string]any{"key": out, "raw": rotated.Raw})
}

// DELETE /users/{id}/keys/{keyID} — admin any, self own. Revokes the key.
func (h *UsersHandler) revokeKey(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	keyID := r.PathValue("keyID")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if !selfOrAdmin(c, id) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	owner, err := h.keys.OwnerOf(r.Context(), keyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if owner != id {
		writeErr(w, http.StatusNotFound, "api key not found")
		return
	}
	if err := h.keys.Revoke(r.Context(), keyID); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not found") || strings.Contains(msg, "already revoked") {
			writeErr(w, http.StatusConflict, "api key not found or already revoked")
		} else {
			writeErr(w, http.StatusInternalServerError, "revoke failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
