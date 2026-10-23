package user

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	RoleAdmin = "admin"
	RoleHuman = "human"
	RoleAgent = "agent"
)

var usernameRe = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

// User is an identity. Credentials live in api_keys, not here.
type User struct {
	ID        string
	Username  string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NormalizeUsername lowercases and trims; usernames are NOCASE-unique in SQLite.
func NormalizeUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidateUsername returns nil if ok.
func ValidateUsername(s string) error {
	n := NormalizeUsername(s)
	if !usernameRe.MatchString(n) {
		return errors.New("username must be 3-32 chars of [a-z0-9_-]")
	}
	return nil
}

// ValidateRole returns nil if role is known. Empty means default human.
func ValidateRole(role string) error {
	switch role {
	case "", RoleAdmin, RoleHuman, RoleAgent:
		return nil
	default:
		return errors.New("role must be admin, human, or agent")
	}
}

// DefaultRole maps "" to human.
func DefaultRole(role string) string {
	if role == "" {
		return RoleHuman
	}
	return role
}
