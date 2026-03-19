package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// Server implements the MCP (Model Context Protocol) 2025 spec with Streamable HTTP transport.
type Server struct {
	registry *tool.Registry
	executor *tool.Executor
	handlers map[string]MethodHandler
	mu       sync.RWMutex
	reqID    atomic.Int64
}

// MethodHandler handles an MCP JSON-RPC method.
type MethodHandler func(params json.RawMessage) (any, error)

// NewServer creates a new MCP server.
func NewServer(registry *tool.Registry, executor ...*tool.Executor) *Server {
	s := &Server{
		registry: registry,
		handlers: make(map[string]MethodHandler),
	}
	if len(executor) > 0 {
		s.executor = executor[0]
	}

	// Register MCP methods
	s.handlers["initialize"] = s.handleInitialize
	s.handlers["tools/list"] = s.handleToolsList
	s.handlers["tools/call"] = s.handleToolsCall
	s.handlers["ping"] = s.handlePing

	return s
}

// ServeHTTP handles MCP requests over Streamable HTTP transport.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONRPCError(w, nil, -32700, "Parse error")
		return
	}

	slog.Debug("MCP request", "method", req.Method, "id", req.ID)

	s.mu.RLock()
	handler, ok := s.handlers[req.Method]
	s.mu.RUnlock()

	if !ok {
		writeJSONRPCError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
		return
	}

	result, err := handler(req.Params)
	if err != nil {
		writeJSONRPCError(w, req.ID, -32000, err.Error())
		return
	}

	writeJSONRPCResult(w, req.ID, result)
}

// --- MCP Method Handlers ---

func (s *Server) handleInitialize(params json.RawMessage) (any, error) {
	return map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "PhantomStrike",
			"version": "1.0.0",
		},
	}, nil
}

func (s *Server) handlePing(params json.RawMessage) (any, error) {
	return map[string]any{}, nil
}

func (s *Server) handleToolsList(params json.RawMessage) (any, error) {
	tools := s.registry.ToMCPTools()
	return map[string]any{"tools": tools}, nil
}

func (s *Server) handleToolsCall(params json.RawMessage) (any, error) {
	var req struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid tool call params: %w", err)
	}

	// Execute through the real tool executor if available
	if s.executor != nil {
		ctx := context.Background()
		result, err := s.executor.Execute(ctx, req.Name, req.Arguments, nil, nil)
		if err != nil {
			return map[string]any{
				"content": []map[string]any{{
					"type": "text",
					"text": fmt.Sprintf("Error executing %s: %v", req.Name, err),
				}},
				"isError": true,
			}, nil
		}

		output := result.Stdout
		if result.Stderr != "" {
			output += "\n--- STDERR ---\n" + result.Stderr
		}

		return map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": output,
			}},
		}, nil
	}

	return map[string]any{
		"content": []map[string]any{{
			"type": "text",
			"text": fmt.Sprintf("Tool %s: executor not configured", req.Name),
		}},
		"isError": true,
	}, nil
}

// --- JSON-RPC types ---

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      any         `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSONRPCResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors still return 200
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	})
}
