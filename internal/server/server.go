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
	"github.com/ersinkoc/phantomstrike/internal/audit"
	"github.com/ersinkoc/phantomstrike/internal/auth"
	"github.com/ersinkoc/phantomstrike/internal/cache"
	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/pkg/ratelimit"
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

	// Initialize audit logger
	auditLogger := audit.NewLogger(db.Pool)
	if err := auditLogger.EnsureTable(context.Background()); err != nil {
		slog.Warn("failed to ensure audit_log table", "error", err)
	}

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
			// Wire token blacklist into auth service
			authSvc.SetBlacklist(cache.NewTokenBlacklist(c))
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

	// OAuth2 endpoints (public — no auth middleware)
	oauth2Handler := auth.NewOAuth2Handler(authSvc, db.Pool, cfg.Auth.OAuth2)
	mux.HandleFunc("GET /api/v1/auth/github", oauth2Handler.HandleGitHubLogin)
	mux.HandleFunc("GET /api/v1/auth/github/callback", oauth2Handler.HandleGitHubCallback)
	mux.HandleFunc("GET /api/v1/auth/google", oauth2Handler.HandleGoogleLogin)
	mux.HandleFunc("GET /api/v1/auth/google/callback", oauth2Handler.HandleGoogleCallback)

	// Initialize rate limiter (100 requests per minute per IP)
	rateLimiter := ratelimit.New(100, time.Minute)

	// Apply global middleware (audit sits after auth, before logging)
	handler := applyMiddleware(mux, cfg, auditLogger, rateLimiter)

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
func applyMiddleware(h http.Handler, cfg *config.Config, auditLogger *audit.Logger, rateLimiter *ratelimit.Limiter) http.Handler {
	// Order: outermost runs first, innermost runs closest to the handler.
	// audit runs after auth (claims are in context) but before logging.
	h = auditLogger.Middleware(h)
	h = recoveryMiddleware(h)
	h = requestIDMiddleware(h)
	h = rateLimiter.Middleware(h)
	h = loggingMiddleware(h)
	h = corsMiddleware(h, cfg.Server.CORSOrigins)
	return h
}
