package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("SANGA_HOST", "")
	t.Setenv("DATABASE_PATH", "")
	t.Setenv("SANGA_ADMIN_KEY_FILE", "")
	t.Setenv("SANGA_ROOT_USERNAME", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8080 || cfg.DatabasePath != "./sanga.db" || cfg.AdminKeyFile != "./admin.key" || cfg.RootUsername != "root" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.Addr() != ":8080" {
		t.Fatalf("addr = %q", cfg.Addr())
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("SANGA_HOST", "127.0.0.1")
	t.Setenv("DATABASE_PATH", "/tmp/db")
	t.Setenv("SANGA_ADMIN_KEY_FILE", "/tmp/key")
	t.Setenv("SANGA_ROOT_USERNAME", "admin")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr() != "127.0.0.1:9090" {
		t.Fatalf("addr = %q", cfg.Addr())
	}
	if cfg.DatabasePath != "/tmp/db" || cfg.AdminKeyFile != "/tmp/key" || cfg.RootUsername != "admin" {
		t.Fatalf("overrides = %+v", cfg)
	}
}

func TestInvalidPort(t *testing.T) {
	t.Setenv("PORT", "not-a-port")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid PORT error")
	}
	t.Setenv("PORT", "70000")
	if _, err := Load(); err == nil {
		t.Fatal("expected out-of-range PORT error")
	}
}
