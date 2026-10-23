package db

import (
	"context"
	"database/sql"
	_ "embed"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// Open opens a SQLite database at path and verifies connectivity.
// path may be a file path or ":memory:" (useful for tests).
func Open(path string) (*sql.DB, error) {
	// modernc.org/sqlite registers driver name "sqlite".
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Single-writer friendly defaults for SQLite.
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, err
	}

	if _, err := database.ExecContext(ctx, `PRAGMA journal_mode=WAL;`); err != nil {
		database.Close()
		return nil, err
	}
	if _, err := database.ExecContext(ctx, `PRAGMA foreign_keys=ON;`); err != nil {
		database.Close()
		return nil, err
	}

	return database, nil
}

// Migrate applies schema.sql (idempotent via IF NOT EXISTS).
func Migrate(database *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := database.ExecContext(ctx, schema)
	return err
}
