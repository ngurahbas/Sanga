package storeutil

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func Now() string {
	return FormatTime(time.Now())
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

func ParseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
