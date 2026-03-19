package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/agent"
	"github.com/ersinkoc/phantomstrike/internal/api"
	"github.com/ersinkoc/phantomstrike/internal/auth"
	"github.com/ersinkoc/phantomstrike/internal/cache"
	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/provider"
	"github.com/ersinkoc/phantomstrike/internal/storage"
	"github.com/ersinkoc/phantomstrike/internal/store"
	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// Server is the main HTTP server for PhantomStrike.
type Server struct {
	cfg     *config.Config
	db      *store.DB
	swarm   *agent.Swarm
	hub     *api.WSHub
	httpSrv *http.Server
}

// New creates a new Server with all routes and middleware configured.
func New(cfg *config.Config, db *store.DB) (*Server, error) {
	// Initialize auth service
	authSvc := auth.NewService(cfg.Auth, db)

	// Initialize provider router
	router := provider.SetupRouter(cfg.Providers)

	// Initialize tool registry
	registry := tool.NewRegistry(cfg.Tools.Dir, db)
	if err := registry.LoadAll(); err != nil {
		slog.Warn("failed to load tools", "error", err)
	}
	if err := registry.SyncToDB(context.Background()); err != nil {
		slog.Warn("failed to sync tools to DB", "error", err)
	}

	// Initialize tool executor
	executor := tool.NewExecutor(registry, db.Pool, cfg.Tools.Docker.Enabled)

	// Initialize agent swarm
	swarm := agent.NewSwarm(cfg.Agent, router, executor, registry)

	// Initialize WebSocket hub
	hub := api.NewWSHub()

	// Build router
	mux := http.NewServeMux()

	// Register API routes
	apiHandler := api.NewHandler(cfg, db, authSvc, swarm, hub, registry)

	// Initialize Redis cache (optional — degrade gracefully)
	if cfg.Redis.URL != "" {
		c, err := cache.New(cfg.Redis.URL)
		if err != nil {
			slog.Warn("redis cache unavailable, running without cache", "error", err)
		} else {
			apiHandler.SetCache(c)
		}
	}

	// Initialize storage provider
	storageProv, err := storage.NewProvider(cfg.Storage)
	if err != nil {
		slog.Warn("storage init failed, using local fallback", "error", err)
	} else {
		apiHandler.SetStorage(storageProv)
	}

	apiHandler.RegisterRoutes(mux)

	// WebSocket endpoint
	mux.Handle("/ws", apiHandler.HandleWebSocket(hub))

	// Apply global middleware
	handler := applyMiddleware(mux, cfg)

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return context.Background()
		},
	}

	return &Server{
		cfg:     cfg,
		db:      db,
		swarm:   swarm,
		hub:     hub,
		httpSrv: httpSrv,
	}, nil
}

// Run starts the HTTP server and blocks until context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		slog.Info("HTTP server listening", "addr", s.httpSrv.Addr)
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down server...")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown with 30s timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	slog.Info("server stopped gracefully")
	return nil
}

// applyMiddleware wraps the handler with global middleware.
func applyMiddleware(h http.Handler, cfg *config.Config) http.Handler {
	// Order: outermost runs first
	h = recoveryMiddleware(h)
	h = requestIDMiddleware(h)
	h = loggingMiddleware(h)
	h = corsMiddleware(h, cfg.Server.CORSOrigins)
	return h
}
