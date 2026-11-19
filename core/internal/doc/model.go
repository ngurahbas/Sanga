package doc

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	VisibilityPublic  = "public"
	VisibilityPrivate = "private"
)

const (
	MaxTitleRunes  = 200
	MaxBodyBytes   = 100 * 1024
	MaxTags        = 10
	MaxShares      = 100
	MaxDocsPerUser = 1000
)

var tagRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

var (
	ErrInvalidTitle         = errors.New("title must be 1-200 chars")
	ErrInvalidBody          = errors.New("body must be 1-100KiB of markdown")
	ErrInvalidVisibility    = errors.New("visibility must be public or private")
	ErrInvalidTag           = errors.New("tags must be 1-10 of [a-z0-9-], max 32 chars each")
	ErrTooManyShares        = errors.New("shared_with must contain at most 100 users")
	ErrSharesRequirePrivate = errors.New("shares are only allowed on private docs")
	ErrCannotShareOwner     = errors.New("cannot share a document with its owner")
	ErrQuotaExceeded        = errors.New("document quota reached")
)

type Doc struct {
	ID         string
	OwnerID    string
	Title      string
	Body       string
	Visibility string
	Tags       []string
	SharedWith []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Patch struct {
	Title      *string   `json:"title"`
	Body       *string   `json:"body"`
	Visibility *string   `json:"visibility"`
	Tags       *[]string `json:"tags"`
}

func NormalizeTag(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func NormalizeTags(tags []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, t := range tags {
		n := NormalizeTag(t)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func ValidateTitle(s string) error {
	n := strings.TrimSpace(s)
	if n == "" {
		return ErrInvalidTitle
	}
	if len([]rune(n)) > MaxTitleRunes {
		return ErrInvalidTitle
	}
	return nil
}

func ValidateBody(s string) error {
	if len(s) == 0 || len(s) > MaxBodyBytes {
		return ErrInvalidBody
	}
	if strings.TrimSpace(s) == "" {
		return ErrInvalidBody
	}
	return nil
}

func ValidateVisibility(v string) error {
	switch v {
	case VisibilityPublic, VisibilityPrivate:
		return nil
	default:
		return ErrInvalidVisibility
	}
}

func DefaultVisibility(v string) string {
	if v == "" {
		return VisibilityPublic
	}
	return v
}

func ValidateTags(tags []string) error {
	if len(tags) > MaxTags {
		return ErrInvalidTag
	}
	for _, t := range tags {
		if !tagRe.MatchString(t) {
			return ErrInvalidTag
		}
	}
	return nil
}
