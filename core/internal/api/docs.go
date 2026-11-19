package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ngurahbas/Sanga/core/internal/auth"
	"github.com/ngurahbas/Sanga/core/internal/doc"
	"github.com/ngurahbas/Sanga/core/internal/httpx"
	"github.com/ngurahbas/Sanga/core/internal/user"
)

type DocsHandler struct {
	docs  *doc.Store
	users *user.Store
	keys  *auth.Store
}

func mountDocs(mux *http.ServeMux, database *sql.DB) {
	h := &DocsHandler{docs: doc.NewStore(database), users: user.NewStore(database), keys: auth.NewStore(database)}
	authed := func(pattern string, fn http.HandlerFunc) {
		mux.Handle(pattern, auth.WithAuth(h.keys, h.users, fn))
	}
	authed("POST /api/docs", h.createDoc)
	authed("GET /api/docs", h.listDocs)
	authed("GET /api/docs/{id}", h.getDoc)
	authed("PATCH /api/docs/{id}", h.patchDoc)
	authed("DELETE /api/docs/{id}", h.deleteDoc)
	authed("PUT /api/docs/{id}/shares", h.addShare)
	authed("DELETE /api/docs/{id}/shares/{userID}", h.removeShare)
}

type docJSON struct {
	ID         string   `json:"id"`
	OwnerID    string   `json:"owner_id"`
	Title      string   `json:"title"`
	Body       string   `json:"body"`
	Visibility string   `json:"visibility"`
	Tags       []string `json:"tags"`
	SharedWith []string `json:"shared_with,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
}

type docSummaryJSON struct {
	ID         string   `json:"id"`
	OwnerID    string   `json:"owner_id"`
	Title      string   `json:"title"`
	Visibility string   `json:"visibility"`
	Tags       []string `json:"tags"`
	SharedWith []string `json:"shared_with,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
}

func toDocJSON(d *doc.Doc, includeShares bool) docJSON {
	tags := d.Tags
	if tags == nil {
		tags = []string{}
	}
	var shared []string
	if includeShares {
		shared = d.SharedWith
		if shared == nil {
			shared = []string{}
		}
	}
	return docJSON{
		ID:         d.ID,
		OwnerID:    d.OwnerID,
		Title:      d.Title,
		Body:       d.Body,
		Visibility: d.Visibility,
		Tags:       tags,
		SharedWith: shared,
		CreatedAt:  d.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:  d.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func toDocSummaryJSON(d *doc.Doc, includeShares bool) docSummaryJSON {
	tags := d.Tags
	if tags == nil {
		tags = []string{}
	}
	var shared []string
	if includeShares {
		shared = d.SharedWith
		if shared == nil {
			shared = []string{}
		}
	}
	return docSummaryJSON{
		ID:         d.ID,
		OwnerID:    d.OwnerID,
		Title:      d.Title,
		Visibility: d.Visibility,
		Tags:       tags,
		SharedWith: shared,
		CreatedAt:  d.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:  d.UpdatedAt.UTC().Format(time.RFC3339Nano),
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
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return nil, nil, false
	}
	d, err := h.docs.ByID(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "doc not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return nil, nil, false
	}
	if !doc.CanRead(d, c.ID, docIsAdmin(c)) {
		httpx.WriteErr(w, http.StatusNotFound, "doc not found")
		return nil, nil, false
	}
	return d, c, true
}

func (h *DocsHandler) createDoc(w http.ResponseWriter, r *http.Request) {
	c, ok := docCaller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		Title      string   `json:"title"`
		Body       string   `json:"body"`
		Visibility string   `json:"visibility"`
		Tags       []string `json:"tags"`
		SharedWith []string `json:"shared_with"`
	}
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	d, err := h.docs.Create(r.Context(), c.ID, body.Title, body.Body, body.Visibility, body.Tags, body.SharedWith)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			httpx.WriteErr(w, http.StatusBadRequest, "unknown shared user")
		case errors.Is(err, doc.ErrQuotaExceeded):
			httpx.WriteErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, doc.ErrInvalidTitle), errors.Is(err, doc.ErrInvalidBody),
			errors.Is(err, doc.ErrInvalidVisibility), errors.Is(err, doc.ErrInvalidTag),
			errors.Is(err, doc.ErrTooManyShares), errors.Is(err, doc.ErrSharesRequirePrivate),
			errors.Is(err, doc.ErrCannotShareOwner):
			httpx.WriteErr(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "create failed")
		}
		return
	}
	w.Header().Set("Location", "/api/docs/"+d.ID)
	httpx.WriteJSON(w, http.StatusCreated, toDocJSON(d, true))
}

func (h *DocsHandler) listDocs(w http.ResponseWriter, r *http.Request) {
	c, ok := docCaller(r)
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "unauthorized")
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
		httpx.WriteErr(w, http.StatusBadRequest, "visibility must be public or private")
		return
	}
	docs, err := h.docs.ListReadable(r.Context(), c.ID, docIsAdmin(c), opts)
	if err != nil {
		httpx.WriteErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]docSummaryJSON, 0, len(docs))
	for _, d := range docs {
		out = append(out, toDocSummaryJSON(d, doc.CanWrite(d, c.ID, docIsAdmin(c))))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *DocsHandler) getDoc(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toDocJSON(d, doc.CanWrite(d, c.ID, docIsAdmin(c))))
}

func (h *DocsHandler) patchDoc(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var body doc.Patch
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	updated, err := h.docs.Update(r.Context(), d.ID, body)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			httpx.WriteErr(w, http.StatusNotFound, "doc not found")
		case errors.Is(err, doc.ErrInvalidTitle), errors.Is(err, doc.ErrInvalidBody),
			errors.Is(err, doc.ErrInvalidVisibility), errors.Is(err, doc.ErrInvalidTag):
			httpx.WriteErr(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "update failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toDocJSON(updated, true))
}

func (h *DocsHandler) deleteDoc(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.docs.Delete(r.Context(), d.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "doc not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "delete failed")
		}
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
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if d.Visibility != doc.VisibilityPrivate {
		httpx.WriteErr(w, http.StatusBadRequest, "shares only for private docs")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	if body.UserID == "" {
		httpx.WriteErr(w, http.StatusBadRequest, "user_id required")
		return
	}
	if body.UserID == d.OwnerID {
		httpx.WriteErr(w, http.StatusBadRequest, "cannot share with the owner")
		return
	}
	if _, err := h.users.ByID(r.Context(), body.UserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusBadRequest, "unknown user")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	if err := h.docs.AddShare(r.Context(), d.ID, body.UserID); err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			httpx.WriteErr(w, http.StatusBadRequest, "unknown doc or user")
		case errors.Is(err, doc.ErrSharesRequirePrivate), errors.Is(err, doc.ErrCannotShareOwner):
			httpx.WriteErr(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteErr(w, http.StatusInternalServerError, "share failed")
		}
		return
	}
	updated, err := h.docs.ByID(r.Context(), d.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "doc not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "lookup failed")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toDocJSON(updated, true))
}

func (h *DocsHandler) removeShare(w http.ResponseWriter, r *http.Request) {
	d, c, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if !doc.CanWrite(d, c.ID, docIsAdmin(c)) {
		httpx.WriteErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.docs.RemoveShare(r.Context(), d.ID, r.PathValue("userID")); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteErr(w, http.StatusNotFound, "share not found")
		} else {
			httpx.WriteErr(w, http.StatusInternalServerError, "unshare failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
