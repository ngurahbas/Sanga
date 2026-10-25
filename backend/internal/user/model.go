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

var (
	ErrInvalidUsername = errors.New("username must be 3-32 chars of [a-z0-9_-]")
	ErrInvalidRole     = errors.New("role must be admin, human, or agent")
)

type User struct {
	ID        string
	Username  string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NormalizeUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func ValidateUsername(s string) error {
	n := NormalizeUsername(s)
	if !usernameRe.MatchString(n) {
		return ErrInvalidUsername
	}
	return nil
}

func ValidateRole(role string) error {
	switch role {
	case "", RoleAdmin, RoleHuman, RoleAgent:
		return nil
	default:
		return ErrInvalidRole
	}
}

func DefaultRole(role string) string {
	if role == "" {
		return RoleHuman
	}
	return role
}
