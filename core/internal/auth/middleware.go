package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/ngurahbas/Sanga/core/internal/httpx"
	"github.com/ngurahbas/Sanga/core/internal/user"
)

type ctxKey int

const (
	keyInfoKey ctxKey = iota
	userKey
)

func WithAuth(keys *Store, users *user.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := FromRequest(r.Header.Get("X-API-Key"), r.Header.Get("Authorization"))
		if raw == "" {
			unauthorized(w, "missing api key")
			return
		}
		k, err := keys.Authenticate(r.Context(), raw)
		if err != nil {
			if errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrKeyRevoked) {
				unauthorized(w, "unauthorized")
				return
			}
			httpx.WriteErr(w, http.StatusInternalServerError, "auth unavailable")
			return
		}
		u, err := users.ByID(r.Context(), k.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				unauthorized(w, "unauthorized")
				return
			}
			httpx.WriteErr(w, http.StatusInternalServerError, "auth unavailable")
			return
		}
		ctx := context.WithValue(r.Context(), keyInfoKey, k)
		ctx = context.WithValue(ctx, userKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	httpx.WriteErr(w, http.StatusUnauthorized, msg)
}

func KeyFromContext(ctx context.Context) (*Key, bool) {
	k, ok := ctx.Value(keyInfoKey).(*Key)
	return k, ok
}

func UserFromContext(ctx context.Context) (*user.User, bool) {
	u, ok := ctx.Value(userKey).(*user.User)
	return u, ok
}

func RequireRole(u *user.User, roles ...string) bool {
	if u == nil {
		return false
	}
	for _, r := range roles {
		if u.Role == r {
			return true
		}
	}
	return false
}
