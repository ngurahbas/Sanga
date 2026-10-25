package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port         int
	DatabasePath string
	AdminKeyFile string
	RootUsername string
}

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

func (c Config) Addr() string {
	return ":" + strconv.Itoa(c.Port)
}
