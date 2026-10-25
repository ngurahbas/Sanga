package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ngurahbas/Sanga/backend/internal/bootstrap"
	"github.com/ngurahbas/Sanga/backend/internal/config"
	"github.com/ngurahbas/Sanga/backend/internal/db"
	httpapi "github.com/ngurahbas/Sanga/backend/internal/http"
)

func main() {
	cfg := config.Load()

	if cfg.DatabasePath != ":memory:" {
		if dir := filepath.Dir(cfg.DatabasePath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Fatalf("mkdir data dir: %v", err)
			}
		}
	}

	if cfg.DatabasePath == "./sanga.db" {
		if _, err := os.Stat(cfg.DatabasePath); os.IsNotExist(err) {
			if _, err2 := os.Stat("data/sanga.db"); err2 == nil {
				log.Printf("warning: data/sanga.db exists but DATABASE_PATH is now %s; move it if you meant to keep existing data", cfg.DatabasePath)
			}
		}
	}

	database, err := db.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		log.Fatalf("migrate db: %v", err)
	}

	res, err := bootstrap.EnsureAdmin(database, cfg.AdminKeyFile, cfg.RootUsername)
	if err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	if res.Created && !res.Imported {
		log.Printf("admin key written to %s (id=%s). Keep it secret.", res.KeyFile, res.KeyID)
	}

	mux := httpapi.NewRouter()
	httpapi.MountUsers(mux, database)
	httpapi.MountDocs(mux, database)

	srv := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("listening on %s (db=%s)", srv.Addr, cfg.DatabasePath)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
}
