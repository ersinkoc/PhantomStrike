package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/mcp"
	"github.com/ersinkoc/phantomstrike/internal/store"
	"github.com/ersinkoc/phantomstrike/internal/tool"
)

const version = "1.0.0"

func main() {
	// Check mode: stdio or http
	mode := "stdio"
	if len(os.Args) > 1 && os.Args[1] == "--http" {
		mode = "http"
	}

	slog.Info("PhantomStrike MCP Server starting", "version", version, "mode", mode)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	setupLogging(cfg.Logging.Level)

	switch mode {
	case "stdio":
		runStdioMode(cfg)
	case "http":
		runHTTPMode(cfg)
	default:
		slog.Error("Unknown mode", "mode", mode)
		os.Exit(1)
	}
}

// runStdioMode runs the MCP server in stdio mode (for Claude Desktop, etc.)
func runStdioMode(cfg *config.Config) {
	// In stdio mode, we create a registry without database
	// Tools are loaded from filesystem

	// Create tool registry
	registry := tool.NewRegistry(cfg.Tools.Dir, nil)
	if err := registry.LoadAll(); err != nil {
		slog.Warn("Failed to load tools", "error", err)
	}

	// Create MCP server
	server := mcp.NewServer(registry)

	slog.Info("MCP Server ready (stdio mode)")

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received")
		cancel()
	}()

	// Process stdin requests
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		if ctx.Err() != nil {
			break
		}

		var req mcp.JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			slog.Error("Failed to decode request", "error", err)
			continue
		}

		slog.Debug("Received request", "method", req.Method, "id", req.ID)

		// Handle the request
		result, err := handleMCRequest(server, &req)

		var resp mcp.JSONRPCResponse
		resp.JSONRPC = "2.0"
		resp.ID = req.ID

		if err != nil {
			resp.Error = &mcp.RPCError{
				Code:    -32000,
				Message: err.Error(),
			}
		} else {
			resp.Result = result
		}

		if err := encoder.Encode(resp); err != nil {
			slog.Error("Failed to encode response", "error", err)
		}
	}

	slog.Info("MCP Server stopped")
}

// runHTTPMode runs the MCP server in HTTP mode
func runHTTPMode(cfg *config.Config) {
	// In HTTP mode, we need database connection
	if cfg.Database.URL == "" {
		slog.Error("DATABASE_URL not configured")
		os.Exit(1)
	}

	ctx := context.Background()
	db, err := store.Connect(ctx, cfg.Database)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Load tools
	registry := tool.NewRegistry(cfg.Tools.Dir, db)
	if err := registry.LoadAll(); err != nil {
		slog.Warn("Failed to load tools", "error", err)
	}

	// Create MCP server
	server := mcp.NewServer(registry)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.Handle("/mcp", server)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	port := cfg.MCP.Server.Port
	if port == 0 {
		port = 8081
	}

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received, stopping server...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server shutdown error", "error", err)
		}
	}()

	slog.Info("MCP Server listening", "port", port, "mode", "http")

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server error", "error", err)
		os.Exit(1)
	}

	slog.Info("MCP Server stopped")
}

// handleMCRequest processes a single MCP request
func handleMCRequest(server *mcp.Server, req *mcp.JSONRPCRequest) (any, error) {
	// The server handles the request through its ServeHTTP method
	// But since we're in stdio mode, we need to handle it differently

	// Create a simple response writer to capture the output
	var result any
	var err error

	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "PhantomStrike",
				"version": version,
			},
		}

	case "tools/list":
		result = map[string]any{
			"tools": []map[string]any{},
		}

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}

		// For now, return a stub response
		result = map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": fmt.Sprintf("Tool '%s' executed with arguments: %v", params.Name, params.Arguments),
			}},
		}

	case "ping":
		result = map[string]any{}

	default:
		return nil, fmt.Errorf("method not found: %s", req.Method)
	}

	return result, err
}

func setupLogging(level string) {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	}))
	slog.SetDefault(logger)
}

// JSONRPCRequest is exported from the mcp package
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is exported from the mcp package
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      any         `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError is exported from the mcp package
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
