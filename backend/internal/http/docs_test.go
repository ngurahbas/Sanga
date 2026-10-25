package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ngurahbas/Sanga/backend/internal/auth"
	"github.com/ngurahbas/Sanga/backend/internal/db"
	"github.com/ngurahbas/Sanga/backend/internal/user"
)

type docFixture struct {
	mux      *http.ServeMux
	admin    *user.User
	human    *user.User
	other    *user.User
	adminRaw string
	humanRaw string
	otherRaw string
}

func newDocFixture(t *testing.T) *docFixture {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	us := &user.Store{DB: database}
	ks := &auth.Store{DB: database}
	admin, _ := us.Create(ctx, "admin1", "admin")
	human, _ := us.Create(ctx, "human1", "human")
	other, _ := us.Create(ctx, "other1", "human")
	aIssued, _ := ks.Issue(ctx, admin.ID, "a")
	hIssued, _ := ks.Issue(ctx, human.ID, "h")
	oIssued, _ := ks.Issue(ctx, other.ID, "o")
	mux := NewRouter()
	MountUsers(mux, database)
	MountDocs(mux, database)
	return &docFixture{mux, admin, human, other, aIssued.Raw, hIssued.Raw, oIssued.Raw}
}

func doDocReq(t *testing.T, mux *http.ServeMux, method, path, rawKey string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if rawKey != "" {
		req.Header.Set("X-API-Key", rawKey)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func doDocList(t *testing.T, mux *http.ServeMux, path, rawKey string) (int, []any) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-API-Key", rawKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	var out []any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func createDoc(t *testing.T, f *docFixture, key string, body map[string]any) string {
	t.Helper()
	code, out := doDocReq(t, f.mux, "POST", "/docs", key, body)
	if code != http.StatusCreated {
		t.Fatalf("create = %d (%v), want 201", code, out)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("missing id in %v", out)
	}
	return id
}

func TestDocPublicReadable(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Pub", "body": "# hello", "tags": []string{"Go"}})
	if code, _ := doDocReq(t, f.mux, "GET", "/docs/"+id, f.otherRaw, nil); code != http.StatusOK {
		t.Fatalf("other read public = %d, want 200", code)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/docs/"+id, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("anon = %d, want 401", code)
	}
}

func TestDocPrivateShareMatrix(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Priv", "body": "secret", "visibility": "private"})
	if code, _ := doDocReq(t, f.mux, "GET", "/docs/"+id, f.otherRaw, nil); code != http.StatusNotFound {
		t.Fatalf("stranger = %d, want 404", code)
	}
	if code, _ := doDocReq(t, f.mux, "PUT", "/docs/"+id+"/shares", f.humanRaw, map[string]string{"user_id": f.other.ID}); code != http.StatusOK {
		t.Fatalf("share = %d, want 200", code)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/docs/"+id, f.otherRaw, nil); code != http.StatusOK {
		t.Fatalf("shared read = %d, want 200", code)
	}
	if code, _ := doDocReq(t, f.mux, "PATCH", "/docs/"+id, f.otherRaw, map[string]string{"title": "hijack"}); code != http.StatusForbidden {
		t.Fatalf("shared write = %d, want 403", code)
	}
	if code, _ := doDocReq(t, f.mux, "PATCH", "/docs/"+id, f.humanRaw, map[string]string{"title": "Priv2"}); code != http.StatusOK {
		t.Fatalf("owner patch = %d, want 200", code)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/docs/"+id, f.adminRaw, nil); code != http.StatusOK {
		t.Fatalf("admin read = %d, want 200", code)
	}
	if code, _ := doDocReq(t, f.mux, "PATCH", "/docs/"+id, f.adminRaw, map[string]string{"title": "ByAdmin"}); code != http.StatusOK {
		t.Fatalf("admin patch = %d, want 200", code)
	}
	if code, _ := doDocReq(t, f.mux, "DELETE", "/docs/"+id+"/shares/"+f.other.ID, f.humanRaw, nil); code != http.StatusNoContent {
		t.Fatalf("unshare = %d, want 204", code)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/docs/"+id, f.otherRaw, nil); code != http.StatusNotFound {
		t.Fatalf("after unshare = %d, want 404", code)
	}
}

func TestDocValidationAndLimits(t *testing.T) {
	f := newDocFixture(t)
	if code, _ := doDocReq(t, f.mux, "POST", "/docs", f.humanRaw, map[string]string{"title": "", "body": "x"}); code != http.StatusBadRequest {
		t.Fatalf("empty title = %d, want 400", code)
	}
	if code, _ := doDocReq(t, f.mux, "POST", "/docs", f.humanRaw, map[string]string{"title": "t", "body": "x", "visibility": "secret"}); code != http.StatusBadRequest {
		t.Fatalf("bad visibility = %d, want 400", code)
	}
	big := strings.Repeat("x", 100*1024+1)
	if code, _ := doDocReq(t, f.mux, "POST", "/docs", f.humanRaw, map[string]string{"title": "t", "body": big}); code != http.StatusBadRequest {
		t.Fatalf("oversize = %d, want 400", code)
	}
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "P", "body": "b"})
	if code, _ := doDocReq(t, f.mux, "PUT", "/docs/"+id+"/shares", f.humanRaw, map[string]string{"user_id": f.other.ID}); code != http.StatusBadRequest {
		t.Fatalf("public share = %d, want 400", code)
	}
	priv := createDoc(t, f, f.humanRaw, map[string]any{"title": "Q", "body": "b", "visibility": "private"})
	if code, _ := doDocReq(t, f.mux, "PUT", "/docs/"+priv+"/shares", f.humanRaw, map[string]string{"user_id": "nope"}); code != http.StatusBadRequest {
		t.Fatalf("unknown share = %d, want 400", code)
	}
}

func TestDocListFilters(t *testing.T) {
	f := newDocFixture(t)
	createDoc(t, f, f.humanRaw, map[string]any{"title": "A", "body": "b", "tags": []string{"t1"}})
	priv := createDoc(t, f, f.humanRaw, map[string]any{"title": "B", "body": "b", "visibility": "private"})
	if code, out := doDocList(t, f.mux, "/docs", f.otherRaw); code != http.StatusOK || len(out) != 1 {
		t.Fatalf("other list = %d len %d, want 200/1", code, len(out))
	}
	if code, out := doDocList(t, f.mux, "/docs?tag=T1", f.otherRaw); code != http.StatusOK || len(out) != 1 {
		t.Fatalf("tag filter = %d len %d, want 200/1", code, len(out))
	}
	if code, out := doDocList(t, f.mux, "/docs?visibility=private", f.otherRaw); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("stranger private filter = %d len %d, want 200/0", code, len(out))
	}
	if code, out := doDocList(t, f.mux, "/docs?visibility=private", f.humanRaw); code != http.StatusOK || len(out) != 1 {
		t.Fatalf("owner private filter = %d len %d, want 200/1", code, len(out))
	}
	_ = priv
}
