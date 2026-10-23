package auth

import (
	"context"
	"net/http"

	"github.com/ngurahbas/Sanga/backend/internal/user"
)

// ctx keys (unexported to avoid collisions).
type ctxKey int

const (
	keyInfoKey ctxKey = iota
	userKey
)

// WithAuth protects routes: validates API key, loads user, injects into context.
// Health and other public routes bypass it by not using this middleware.
func WithAuth(keys *Store, users *user.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := FromRequest(r.Header.Get("X-API-Key"), r.Header.Get("Authorization"))
		if raw == "" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		k, err := keys.Authenticate(r.Context(), raw)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		u, err := users.ByID(r.Context(), k.UserID)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), keyInfoKey, k)
		ctx = context.WithValue(ctx, userKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// KeyFromContext returns the authenticated key, if present.
func KeyFromContext(ctx context.Context) (*Key, bool) {
	k, ok := ctx.Value(keyInfoKey).(*Key)
	return k, ok
}

// UserFromContext returns the authenticated user, if present.
func UserFromContext(ctx context.Context) (*user.User, bool) {
	u, ok := ctx.Value(userKey).(*user.User)
	return u, ok
}

// RequireRole is a helper for handlers: true if user has one of the roles.
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
