package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ngurahbas/Sanga/core/internal/bootstrap"
	"github.com/ngurahbas/Sanga/core/internal/config"
	"github.com/ngurahbas/Sanga/core/internal/db"
	"github.com/ngurahbas/Sanga/core/server"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if cfg.DatabasePath != ":memory:" {
		if dir := filepath.Dir(cfg.DatabasePath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("mkdir data dir: %w", err)
			}
		}
	}

	database, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		return fmt.Errorf("migrate db: %w", err)
	}
	if err := db.Secure(cfg.DatabasePath); err != nil {
		return fmt.Errorf("secure db files: %w", err)
	}

	res, err := bootstrap.EnsureAdmin(database, cfg.AdminKeyFile, cfg.RootUsername)
	if err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	if res.Created && !res.Imported {
		log.Printf("admin key written to %s (id=%s). Keep it secret.", res.KeyFile, res.KeyID)
	}

	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           server.NewHandler(database),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (db=%s)", srv.Addr, cfg.DatabasePath)
		errCh <- srv.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-stop:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
