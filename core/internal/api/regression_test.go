package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPatchEmptyVisibilityRejected(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Private", "body": "secret", "visibility": "private"})
	code, out := doDocReq(t, f.mux, "PATCH", "/api/docs/"+id, f.humanRaw, map[string]any{"visibility": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("empty visibility = %d (%v), want 400", code, out)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/api/docs/"+id, f.otherRaw, nil); code != http.StatusNotFound {
		t.Fatalf("stranger read = %d, want 404", code)
	}
}

func TestPatchTitleDoesNotOverwriteBody(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Original", "body": "original body"})
	if code, out := doDocReq(t, f.mux, "PATCH", "/api/docs/"+id, f.humanRaw, map[string]any{"title": "Renamed"}); code != http.StatusOK {
		t.Fatalf("patch = %d (%v), want 200", code, out)
	}
	code, out := doDocReq(t, f.mux, "GET", "/api/docs/"+id, f.humanRaw, nil)
	if code != http.StatusOK {
		t.Fatalf("get = %d, want 200", code)
	}
	if out["body"] != "original body" || out["title"] != "Renamed" {
		t.Fatalf("doc = %v", out)
	}
}

func TestDeleteDoc(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Delete", "body": "body"})
	if code, _ := doDocReq(t, f.mux, "DELETE", "/api/docs/"+id, f.otherRaw, nil); code != http.StatusForbidden {
		t.Fatalf("stranger delete = %d, want 403", code)
	}
	if code, _ := doDocReq(t, f.mux, "DELETE", "/api/docs/"+id, f.humanRaw, nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", code)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/api/docs/"+id, f.humanRaw, nil); code != http.StatusNotFound {
		t.Fatalf("after delete = %d, want 404", code)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	f := newDocFixture(t)
	body := map[string]string{"title": "Too big", "body": strings.Repeat("x", (1<<20)+1)}
	code, _ := doDocReq(t, f.mux, "POST", "/api/docs", f.humanRaw, body)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize request = %d, want 413", code)
	}
}

func TestListKeysCrossUserForbidden(t *testing.T) {
	f := newDocFixture(t)
	if code, _ := doDocReq(t, f.mux, "GET", "/api/users/"+f.admin.ID+"/keys", f.humanRaw, nil); code != http.StatusForbidden {
		t.Fatalf("cross-user key list = %d, want 403", code)
	}
	if code, _ := doDocReq(t, f.mux, "GET", "/api/users/"+f.admin.ID+"/keys", f.adminRaw, nil); code != http.StatusOK {
		t.Fatalf("admin key list = %d, want 200", code)
	}
}

func TestCannotRevokeLastAdminKeyOverHTTP(t *testing.T) {
	f := newDocFixture(t)
	code, _ := doDocReq(t, f.mux, "DELETE", "/api/users/"+f.admin.ID+"/keys/"+keyIDOf(t, f.adminRaw), f.adminRaw, nil)
	if code != http.StatusConflict {
		t.Fatalf("revoke last admin key = %d, want 409", code)
	}
}

func TestSharedWithHiddenFromNonWriters(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{
		"title": "Shared", "body": "body", "visibility": "private", "shared_with": []string{f.other.ID},
	})
	_, out := doDocReq(t, f.mux, "GET", "/api/docs/"+id, f.otherRaw, nil)
	if _, ok := out["shared_with"]; ok {
		t.Fatalf("reader sees shared_with: %v", out)
	}
	_, out = doDocReq(t, f.mux, "GET", "/api/docs/"+id, f.humanRaw, nil)
	if _, ok := out["shared_with"]; !ok {
		t.Fatalf("owner missing shared_with: %v", out)
	}
}

func TestBearerAuth(t *testing.T) {
	f := newDocFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+f.humanRaw)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer auth = %d, want 200", rec.Code)
	}
}

func TestTrailingJSONRejected(t *testing.T) {
	f := newDocFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/users/"+f.human.ID+"/keys", bytes.NewBufferString(`{"name":"a"}{"name":"b"}`))
	req.Header.Set("X-API-Key", f.humanRaw)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON = %d, want 400", rec.Code)
	}
}

func TestUnknownPatchFieldRejected(t *testing.T) {
	f := newDocFixture(t)
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Doc", "body": "body"})
	code, _ := doDocReq(t, f.mux, "PATCH", "/api/docs/"+id, f.humanRaw, map[string]any{"unknown": true})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", code)
	}
}

func TestCreatePublicDocWithSharesRejected(t *testing.T) {
	f := newDocFixture(t)
	code, out := doDocReq(t, f.mux, "POST", "/api/docs", f.humanRaw, map[string]any{
		"title": "Public", "body": "body", "visibility": "public", "shared_with": []string{f.other.ID},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("public shares = %d (%v), want 400", code, out)
	}
}

func TestShareRules(t *testing.T) {
	f := newDocFixture(t)
	if code, _ := doDocReq(t, f.mux, "POST", "/api/docs", f.humanRaw, map[string]any{
		"title": "Owned", "body": "body", "visibility": "private", "shared_with": []string{f.human.ID},
	}); code != http.StatusBadRequest {
		t.Fatalf("create share owner = %d, want 400", code)
	}
	id := createDoc(t, f, f.humanRaw, map[string]any{"title": "Private", "body": "body", "visibility": "private"})
	if code, _ := doDocReq(t, f.mux, "PUT", "/api/docs/"+id+"/shares", f.humanRaw, map[string]string{"user_id": f.human.ID}); code != http.StatusBadRequest {
		t.Fatalf("share owner = %d, want 400", code)
	}
	if code, _ := doDocReq(t, f.mux, "DELETE", "/api/docs/"+id+"/shares/"+f.other.ID, f.humanRaw, nil); code != http.StatusNotFound {
		t.Fatalf("remove missing share = %d, want 404", code)
	}
}

func TestListOmitsBodies(t *testing.T) {
	f := newDocFixture(t)
	createDoc(t, f, f.humanRaw, map[string]any{"title": "Doc", "body": "large body"})
	code, out := doDocList(t, f.mux, "/api/docs", f.humanRaw)
	if code != http.StatusOK || len(out) != 1 {
		t.Fatalf("list = %d len %d", code, len(out))
	}
	docMap, ok := out[0].(map[string]any)
	if !ok {
		t.Fatalf("doc = %T", out[0])
	}
	if _, exists := docMap["body"]; exists {
		t.Fatalf("list includes body: %v", docMap)
	}
}

func TestAdminSeesAllDocs(t *testing.T) {
	f := newDocFixture(t)
	createDoc(t, f, f.humanRaw, map[string]any{"title": "Private", "body": "body", "visibility": "private"})
	code, out := doDocList(t, f.mux, "/api/docs", f.adminRaw)
	if code != http.StatusOK || len(out) != 1 {
		t.Fatalf("admin list = %d len %d, want 200/1", code, len(out))
	}
}

func TestLocationPrefix(t *testing.T) {
	f := newDocFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBufferString(`{"username":"agent-7","role":"agent"}`))
	req.Header.Set("X-API-Key", f.adminRaw)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d", rec.Code)
	}
	var out map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/api/users/") {
		t.Fatalf("location = %q", loc)
	}
}
