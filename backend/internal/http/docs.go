package http

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ngurahbas/Sanga/backend/internal/auth"
	"github.com/ngurahbas/Sanga/backend/internal/doc"
	"github.com/ngurahbas/Sanga/backend/internal/user"
)

type DocsHandler struct {
	docs  *doc.Store
	users *user.Store
	keys  *auth.Store
}

func MountDocs(mux *http.ServeMux, database *sql.DB) {
	h := &DocsHandler{docs: &doc.Store{DB: database}, users: &user.Store{DB: database}, keys: &auth.Store{DB: database}}
	authed := func(pattern string, fn http.HandlerFunc) {
		mux.Handle(pattern, auth.WithAuth(h.keys, h.users, fn))
	}
	authed("POST /docs", h.createDoc)
	authed("GET /docs", h.listDocs)
	authed("GET /docs/{id}", h.getDoc)
	authed("PATCH /docs/{id}", h.patchDoc)
	authed("DELETE /docs/{id}", h.deleteDoc)
	authed("PUT /docs/{id}/shares", h.addShare)
	authed("DELETE /docs/{id}/shares/{userID}", h.removeShare)
}

type docJSON struct {
	ID         string   `json:"id"`
	OwnerID    string   `json:"owner_id"`
	Title      string   `json:"title"`
	Body       string   `json:"body"`
	Visibility string   `json:"visibility"`
	Tags       []string `json:"tags"`
	SharedWith []string `json:"shared_with"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
}

func toDocJSON(d *doc.Doc) docJSON {
	tags := d.Tags
	if tags == nil {
		tags = []string{}
	}
	shared := d.SharedWith
	if shared == nil {
		shared = []string{}
	}
	return docJSON{
		ID: d.ID, OwnerID: d.OwnerID, Title: d.Title, Body: d.Body,
		Visibility: d.Visibility, Tags: tags, SharedWith: shared,
		CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: d.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func docCaller(r *http.Request) (*user.User, bool) {
	return auth.UserFromContext(r.Context())
}

func docIsAdmin(c *user.User) bool {
	return auth.RequireRole(c, user.RoleAdmin)
}

func (h *DocsHandler) loadVisible(w http.ResponseWriter, r *http.Request) (*doc.Doc, *user.User, bool) {
	c, ok := docCaller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return nil, nil, false
	}
	d, err := h.docs.ByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "doc not found")
		return nil, nil, false
	}
	if !doc.CanRead(d, c.ID, docIsAdmin(c)) {
		writeErr(w, http.StatusNotFound, "doc not found")
		return nil, nil, false
	}
	return d, c, true
}

func (h *DocsHandler) createDoc(w http.ResponseWriter, r *http.Request) {
	c, ok := docCaller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		Title      string   `json:"title"`
		Body       string   `json:"body"`
		Visibility string   `json:"visibility"`
		Tags       []string `json:"tags"`
		SharedWith []string `json:"shared_with"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	d, err := h.docs.Create(r.Context(), c.ID, body.Title, body.Body, body.Visibility, body.Tags, body.SharedWith)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeErr(w, http.StatusBadRequest, "unknown shared user")
		case errors.Is(err, doc.ErrInvalidTitle), errors.Is(err, doc.ErrInvalidBody),
			errors.Is(err, doc.ErrInvalidVisibility), errors.Is(err, doc.ErrInvalidTag):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "create failed")
		}
		return
	}
	w.Header().Set("Location", "/docs/"+d.ID)
	writeJSON(w, http.StatusCreated, toDocJSON(d))
}

func (h *DocsHandler) listDocs(w http.ResponseWriter, r *http.Request) {
	c, ok := docCaller(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	opts := doc.ListOptions{
		Limit: limit, Offset: offset,
		Tag: q.Get("tag"), OwnerID: q.Get("owner"), Visibility: q.Get("visibility"),
	}
	if opts.Visibility != "" && opts.Visibility != doc.VisibilityPublic && opts.Visibility != doc.VisibilityPrivate {
		writeErr(w, http.StatusBadRequest, "visibility must be public or private")
		return
	}
	docs, err := h.docs.ListReadable(r.Context(), c.ID, docIsAdmin(c), opts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]docJSON, 0, len(docs))
	for _, d := range docs {
		out = append(out, toDocJSON(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *DocsHandler) getDoc(w http.ResponseWriter, r *http.Request) {
	d, _, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, toDocJSON(d))
}

func (h *DocsHandler) patchDoc(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Title      *string   `json:"title"`
		Body       *string   `json:"body"`
		Visibility *string   `json:"visibility"`
		Tags       *[]string `json:"tags"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	title, bdy, vis, tags := d.Title, d.Body, d.Visibility, d.Tags
	if body.Title != nil {
		title = *body.Title
	}
	if body.Body != nil {
		bdy = *body.Body
	}
	if body.Visibility != nil {
		vis = *body.Visibility
	}
	if body.Tags != nil {
		tags = *body.Tags
	}
	updated, err := h.docs.Update(r.Context(), d.ID, title, bdy, vis, tags)
	if err != nil {
		switch {
		case errors.Is(err, doc.ErrInvalidTitle), errors.Is(err, doc.ErrInvalidBody),
			errors.Is(err, doc.ErrInvalidVisibility), errors.Is(err, doc.ErrInvalidTag):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "update failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, toDocJSON(updated))
}

func (h *DocsHandler) deleteDoc(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.docs.Delete(r.Context(), d.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DocsHandler) addShare(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if d.Visibility != doc.VisibilityPrivate {
		writeErr(w, http.StatusBadRequest, "shares only for private docs")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.UserID == "" {
		writeErr(w, http.StatusBadRequest, "user_id required")
		return
	}
	if _, err := h.users.ByID(r.Context(), body.UserID); err != nil {
		writeErr(w, http.StatusBadRequest, "unknown user")
		return
	}
	if err := h.docs.AddShare(r.Context(), d.ID, body.UserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusBadRequest, "unknown doc or user")
		} else {
			writeErr(w, http.StatusInternalServerError, "share failed")
		}
		return
	}
	updated, err := h.docs.ByID(r.Context(), d.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, toDocJSON(updated))
}

func (h *DocsHandler) removeShare(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.docs.RemoveShare(r.Context(), d.ID, r.PathValue("userID")); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "share not found")
		} else {
			writeErr(w, http.StatusInternalServerError, "unshare failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
