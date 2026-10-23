package config

import (
	"os"
	"strconv"
)

// Config holds server runtime settings from env.
type Config struct {
	Port         int
	DatabasePath string
	AdminKeyFile string
	RootUsername string
}

// Load reads env with sane defaults.
// PORT: (default 8080)
// DATABASE_PATH: (default "./sanga.db")
// SANGA_ADMIN_KEY_FILE: (default "./admin.key")
// SANGA_ROOT_USERNAME: (default "root")
func Load() Config {
	port := 8080
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}

	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./sanga.db"
	}

	keyFile := os.Getenv("SANGA_ADMIN_KEY_FILE")
	if keyFile == "" {
		keyFile = "./admin.key"
	}

	root := os.Getenv("SANGA_ROOT_USERNAME")
	if root == "" {
		root = "root"
	}

	return Config{
		Port:         port,
		DatabasePath: dbPath,
		AdminKeyFile: keyFile,
		RootUsername: root,
	}
}

// Addr returns ":<port>" for net/http.
func (c Config) Addr() string {
	return ":" + strconv.Itoa(c.Port)
}
