package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ngurahbas/Sanga/backend/internal/auth"
	"github.com/ngurahbas/Sanga/backend/internal/db"
	"github.com/ngurahbas/Sanga/backend/internal/user"
)

type fixture struct {
	mux      *http.ServeMux
	admin    *user.User
	human    *user.User
	adminRaw string
	humanRaw string
}

func newFixture(t *testing.T) *fixture {
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
	admin, err := us.Create(ctx, "admin1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	human, err := us.Create(ctx, "human1", "human")
	if err != nil {
		t.Fatal(err)
	}
	aIssued, err := ks.Issue(ctx, admin.ID, "a")
	if err != nil {
		t.Fatal(err)
	}
	hIssued, err := ks.Issue(ctx, human.ID, "h")
	if err != nil {
		t.Fatal(err)
	}
	mux := NewRouter()
	MountUsers(mux, database)
	return &fixture{mux, admin, human, aIssued.Raw, hIssued.Raw}
}

func doReq(t *testing.T, mux *http.ServeMux, method, path, rawKey string, body any) (int, map[string]any) {
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

func TestCreateUserAdminOnly(t *testing.T) {
	f := newFixture(t)
	// Admin creates.
	code, out := doReq(t, f.mux, "POST", "/users", f.adminRaw, map[string]string{"username": "agent-9", "role": "agent"})
	if code != http.StatusCreated {
		t.Fatalf("create = %d (%v), want 201", code, out)
	}
	// Duplicate.
	if code, _ := doReq(t, f.mux, "POST", "/users", f.adminRaw, map[string]string{"username": "agent-9"}); code != http.StatusConflict {
		t.Fatalf("duplicate = %d, want 409", code)
	}
	// Bad role.
	if code, _ := doReq(t, f.mux, "POST", "/users", f.adminRaw, map[string]string{"username": "x1-y2", "role": "god"}); code != http.StatusBadRequest {
		t.Fatalf("bad role = %d, want 400", code)
	}
	// Non-admin.
	if code, _ := doReq(t, f.mux, "POST", "/users", f.humanRaw, map[string]string{"username": "zz-top"}); code != http.StatusForbidden {
		t.Fatalf("human create = %d, want 403", code)
	}
	// No key.
	if code, _ := doReq(t, f.mux, "POST", "/users", "", map[string]string{"username": "zz-top"}); code != http.StatusUnauthorized {
		t.Fatalf("anon create = %d, want 401", code)
	}
}

func TestListGetOpen(t *testing.T) {
	f := newFixture(t)
	if code, _ := doReq(t, f.mux, "GET", "/users", f.humanRaw, nil); code != http.StatusOK {
		t.Fatalf("list = %d, want 200", code)
	}
	if code, _ := doReq(t, f.mux, "GET", "/users/"+f.admin.ID, f.humanRaw, nil); code != http.StatusOK {
		t.Fatalf("get other = %d, want 200", code)
	}
	if code, _ := doReq(t, f.mux, "GET", "/users/me", f.humanRaw, nil); code != http.StatusOK {
		t.Fatalf("me = %d, want 200", code)
	}
	if code, out := doReq(t, f.mux, "GET", "/users/me", f.humanRaw, nil); code == http.StatusOK {
		u := out["user"].(map[string]any)
		if u["username"] != "human1" || out["active_keys"].(float64) != 1 {
			t.Fatalf("me = %v", out)
		}
	}
	if code, _ := doReq(t, f.mux, "GET", "/users", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("anon list = %d, want 401", code)
	}
	if code, _ := doReq(t, f.mux, "GET", "/users/nope", f.humanRaw, nil); code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404", code)
	}
}

func TestDeleteUser(t *testing.T) {
	f := newFixture(t)
	// Non-admin cannot delete.
	if code, _ := doReq(t, f.mux, "DELETE", "/users/"+f.human.ID, f.humanRaw, nil); code != http.StatusForbidden {
		t.Fatalf("self delete = %d, want 403", code)
	}
	// Admin deletes human: human key must stop working.
	if code, _ := doReq(t, f.mux, "DELETE", "/users/"+f.human.ID, f.adminRaw, nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", code)
	}
	if code, _ := doReq(t, f.mux, "GET", "/users/me", f.humanRaw, nil); code != http.StatusUnauthorized {
		t.Fatalf("deleted key = %d, want 401", code)
	}
	// Last admin cannot be deleted.
	if code, _ := doReq(t, f.mux, "DELETE", "/users/"+f.admin.ID, f.adminRaw, nil); code != http.StatusConflict {
		t.Fatalf("last admin = %d, want 409", code)
	}
}

func TestIssueCapAndScope(t *testing.T) {
	f := newFixture(t)
	// Self issue works.
	code, out := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys", f.humanRaw, map[string]string{"name": "extra"})
	if code != http.StatusCreated {
		t.Fatalf("self issue = %d (%v), want 201", code, out)
	}
	if out["raw"] == nil || len(out["raw"].(string)) < 20 {
		t.Fatal("missing raw")
	}
	// Cross-user issue forbidden.
	if code, _ := doReq(t, f.mux, "POST", "/users/"+f.admin.ID+"/keys", f.humanRaw, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("cross issue = %d, want 403", code)
	}
	// Admin issues for human.
	if code, _ := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys", f.adminRaw, map[string]string{}); code != http.StatusCreated {
		t.Fatalf("admin issue = %d, want 201", code)
	}
	// Fill to cap (human now has 3 active: fixture + self + admin-issued).
	for i := 0; i < 7; i++ {
		if code, _ := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys", f.adminRaw, map[string]string{}); code != http.StatusCreated {
			t.Fatalf("fill %d = %d, want 201", i, code)
		}
	}
	if code, _ := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys", f.adminRaw, map[string]string{}); code != http.StatusConflict {
		t.Fatalf("over cap = %d, want 409", code)
	}
}

func TestRotateAtCap(t *testing.T) {
	f := newFixture(t)
	// Fill human to the cap (fixture key + 9 more = 10 active).
	for i := 0; i < 9; i++ {
		if code, _ := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys", f.adminRaw, map[string]string{}); code != http.StatusCreated {
			t.Fatalf("fill %d = %d, want 201", i, code)
		}
	}
	// Rotation is net-zero: must still succeed at cap.
	oldRaw := f.humanRaw
	code, out := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys/"+keyIDOf(t, oldRaw)+"/rotate", oldRaw, nil)
	if code != http.StatusCreated {
		t.Fatalf("rotate at cap = %d (%v), want 201", code, out)
	}
	if code, _ := doReq(t, f.mux, "GET", "/users/me", oldRaw, nil); code != http.StatusUnauthorized {
		t.Fatalf("old key = %d, want 401", code)
	}
}

func TestRotateAndRevoke(t *testing.T) {
	f := newFixture(t)
	// List keys (metadata, no raw).
	code, _ := doReq(t, f.mux, "GET", "/users/"+f.human.ID+"/keys", f.humanRaw, nil)
	if code != http.StatusOK {
		t.Fatalf("list keys = %d, want 200", code)
	}
	// Self rotate.
	oldRaw := f.humanRaw
	code, out := doReq(t, f.mux, "POST", "/users/"+f.human.ID+"/keys/"+keyIDOf(t, f.humanRaw)+"/rotate", f.humanRaw, map[string]string{})
	if code != http.StatusCreated {
		t.Fatalf("rotate = %d (%v), want 201", code, out)
	}
	newRaw := out["raw"].(string)
	if code, _ := doReq(t, f.mux, "GET", "/users/me", oldRaw, nil); code != http.StatusUnauthorized {
		t.Fatalf("old key = %d, want 401", code)
	}
	if code, _ := doReq(t, f.mux, "GET", "/users/me", newRaw, nil); code != http.StatusOK {
		t.Fatalf("new key = %d, want 200", code)
	}
	// Cross-user rotate forbidden.
	if code, _ := doReq(t, f.mux, "POST", "/users/"+f.admin.ID+"/keys/whatever/rotate", newRaw, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("cross rotate = %d, want 403", code)
	}
	// Revoke self key, then double revoke -> 409.
	kid := keyIDOf(t, newRaw)
	if code, _ := doReq(t, f.mux, "DELETE", "/users/"+f.human.ID+"/keys/"+kid, newRaw, nil); code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", code)
	}
	if code, _ := doReq(t, f.mux, "DELETE", "/users/"+f.human.ID+"/keys/"+kid, f.adminRaw, nil); code != http.StatusConflict {
		t.Fatalf("double revoke = %d, want 409", code)
	}
}

// keyIDOf parses "<id>.<secret>".
func keyIDOf(t *testing.T, raw string) string {
	t.Helper()
	for i, c := range raw {
		if c == '.' {
			return raw[:i]
		}
	}
	t.Fatal("bad raw")
	return ""
}
