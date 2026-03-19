package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/pkg/logger"
	"github.com/ersinkoc/phantomstrike/internal/pkg/version"
	"github.com/ersinkoc/phantomstrike/internal/server"
	"github.com/ersinkoc/phantomstrike/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Initialize structured logger
	log := logger.New(cfg.Logging.Level, cfg.Logging.Format)
	slog.SetDefault(log)

	slog.Info("starting PhantomStrike",
		"version", version.Version,
		"commit", version.Commit,
	)

	// Setup graceful shutdown context
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to PostgreSQL
	db, err := store.Connect(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()

	// Run migrations
	if cfg.Database.MigrationAuto {
		if err := store.Migrate(db); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
		slog.Info("database migrations completed")
	}

	// Create and start server
	srv, err := server.New(cfg, db)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	return srv.Run(ctx)
}
