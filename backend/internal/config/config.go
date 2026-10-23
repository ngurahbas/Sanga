package config

import (
	"os"
	"strconv"
)

// Config holds server runtime settings from env.
type Config struct {
	Port         int
	DatabasePath string
}

// Load reads env with sane defaults.
// PORT: e.g. "8080" (default 8080)
// DATABASE_PATH: e.g. "data/sanga.db" (default "data/sanga.db")
func Load() Config {
	port := 8080
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "data/sanga.db"
	}

	return Config{
		Port:         port,
		DatabasePath: dbPath,
	}
}

// Addr returns ":<port>" for net/http.
func (c Config) Addr() string {
	return ":" + strconv.Itoa(c.Port)
}
