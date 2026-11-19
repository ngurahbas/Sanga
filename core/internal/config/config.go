package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

type Config struct {
	Host         string
	Port         int
	DatabasePath string
	AdminKeyFile string
	RootUsername string
}

func Load() (Config, error) {
	port := 8080
	if v := os.Getenv("PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p <= 0 || p > 65535 {
			return Config{}, fmt.Errorf("invalid PORT %q", v)
		}
		port = p
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
		Host:         os.Getenv("SANGA_HOST"),
		Port:         port,
		DatabasePath: dbPath,
		AdminKeyFile: keyFile,
		RootUsername: root,
	}, nil
}

func (c Config) Addr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}
