package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ngurahbas/Sanga/core/internal/auth"
	"github.com/ngurahbas/Sanga/core/internal/httpx"
	"github.com/ngurahbas/Sanga/core/internal/user"
	sqlite3 "modernc.org/sqlite"
)

type UsersHandler struct {
	users *user.Store
	keys  *auth.Store
}

func mountUsers(mux *http.ServeMux, database *sql.DB) {
	h := &UsersHandler{users: user.NewStore(database), keys: auth.NewStore(database)}
	authed := func(pattern string, fn http.HandlerFunc) {
		mux.Handle(pattern, auth.WithAuth(h.keys, h.users, fn))
	}
	authed("POST /api/users", h.createUser)
	authed("GET /api/users", h.listUsers)
	authed("GET /api/users/me", h.me)
	authed("GET /api/users/{id}", h.getUser)
	authed("DELETE /api/users/{id}", h.deleteUser)
	authed("POST /api/users/{id}/keys", h.issueKey)
	authed("GET /api/users/{id}/keys", h.listKeys)
	authed("POST /api/users/{id}/keys/{keyID}/rotate", h.rotateKey)
	authed("DELETE /api/users/{id}/keys/{keyID}", h.revokeKey)
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
	return userJSON{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: u.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func strptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func toKeyJSON(k *auth.Key) keyJSON {
	return keyJSON{
		ID:         k.ID,
		KeyPrefix:  k.KeyPrefix,
		Name:       k.Name,
		RevokedAt:  strptr(k.RevokedAt),
		LastUsedAt: strptr(k.LastUsedAt),
		CreatedAt:  k.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func caller(r *http.Request) (*user.User, bool) {
	return auth.UserFromContext(r.Context())
}

func selfOrAdmin(c *user.User, targetID string) bool {
	if auth.RequireRole(c, user.RoleAdmin) {
		return true
	}
	return c.ID == targetID
}

func isDuplicate(err error) bool {
	var sqliteErr *sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code() == 2067 || sqliteErr.Code() == 1555
	}
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (h *UsersHandler) createUser(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok || !auth.RequireRole(c, user.RoleAdmin) {
		httpx.WriteErr(w, http.StatusForbidden, "admin only")
		return
	}
	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	u, err := h.users.Create(r.Context(), body.Username, body.Role)
	if err != nil {
		switch {
		case isDuplicate(err):
			httpx.WriteErr(w, http.StatusConflict, "username taken")
		case errors.Is(err, user.ErrInvalidUsername), errors.Is(err, user.ErrInvalidRole):
			httpx.WriteErr(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "create failed")
		}
		return
	}
	w.Header().Set("Location", "/api/users/"+u.ID)
	httpx.WriteJSON(w, http.StatusCreated, toUserJSON(u))
}

func (h *UsersHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := caller(r); !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	users, err := h.users.List(r.Context(), limit, offset)
	if err != nil {
		httpx.WriteErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *UsersHandler) me(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	n, err := h.keys.ActiveCount(r.Context(), c.ID)
	if err != nil {
		httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": toUserJSON(c), "active_keys": n})
}

func (h *UsersHandler) getUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := caller(r); !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	u, err := h.users.ByID(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "user not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toUserJSON(u))
}

func (h *UsersHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok || !auth.RequireRole(c, user.RoleAdmin) {
		httpx.WriteErr(w, http.StatusForbidden, "admin only")
		return
	}
	err := h.users.Delete(r.Context(), r.PathValue("id"))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, sql.ErrNoRows):
		httpx.WriteErr(w, http.StatusNotFound, "user not found")
	case errors.Is(err, user.ErrLastAdmin):
		httpx.WriteErr(w, http.StatusConflict, "cannot delete the last admin")
	default:
		httpx.WriteErr(w, http.StatusInternalServerError, "delete failed")
	}
}

func (h *UsersHandler) issueKey(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "user not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if !selfOrAdmin(c, id) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	issued, err := h.keys.Issue(r.Context(), id, body.Name)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrKeyLimit):
			httpx.WriteErr(w, http.StatusConflict, "key limit reached")
		case errors.Is(err, auth.ErrInvalidKeyName):
			httpx.WriteErr(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "issue failed")
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"key": toKeyJSON(&issued.Key), "raw": issued.Raw})
}

func (h *UsersHandler) listKeys(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "user not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if !selfOrAdmin(c, id) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	keys, err := h.keys.ListByUser(r.Context(), id)
	if err != nil {
		httpx.WriteErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]keyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, toKeyJSON(k))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *UsersHandler) rotateKey(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	keyID := r.PathValue("keyID")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "user not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if !selfOrAdmin(c, id) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	existing, err := h.keys.ByID(r.Context(), keyID)
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			httpx.WriteErr(w, http.StatusNotFound, "api key not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if existing.UserID != id {
		httpx.WriteErr(w, http.StatusNotFound, "api key not found")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" {
		body.Name = existing.Name
	}
	rotated, err := h.keys.Rotate(r.Context(), id, keyID, body.Name)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrKeyNotFound):
			httpx.WriteErr(w, http.StatusNotFound, "api key not found")
		case errors.Is(err, auth.ErrKeyAlreadyRevoked):
			httpx.WriteErr(w, http.StatusConflict, "api key already revoked")
		case errors.Is(err, auth.ErrInvalidKeyName):
			httpx.WriteErr(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "rotate failed")
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"key": toKeyJSON(&rotated.Key), "raw": rotated.Raw})
}

func (h *UsersHandler) revokeKey(w http.ResponseWriter, r *http.Request) {
	c, ok := caller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := r.PathValue("id")
	keyID := r.PathValue("keyID")
	if _, err := h.users.ByID(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "user not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if !selfOrAdmin(c, id) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	owner, err := h.keys.OwnerOf(r.Context(), keyID)
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			httpx.WriteErr(w, http.StatusNotFound, "api key not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if owner != id {
		httpx.WriteErr(w, http.StatusNotFound, "api key not found")
		return
	}
	if err := h.keys.Revoke(r.Context(), keyID); err != nil {
		switch {
		case errors.Is(err, auth.ErrKeyNotFound):
			httpx.WriteErr(w, http.StatusNotFound, "api key not found")
		case errors.Is(err, auth.ErrKeyAlreadyRevoked):
			httpx.WriteErr(w, http.StatusConflict, "api key already revoked")
		case errors.Is(err, auth.ErrLastAdminKey):
			httpx.WriteErr(w, http.StatusConflict, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "revoke failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
