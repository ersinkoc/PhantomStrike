package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// newTestRegistry creates a tool.Registry pre-loaded with definitions for testing.
func newTestRegistry(defs ...*tool.Definition) *tool.Registry {
	reg := tool.NewRegistry("", nil)
	for _, d := range defs {
		reg.Register(d)
	}
	return reg
}

func doRPC(t *testing.T, server *Server, method string, params any) JSONRPCResponse {
	t.Helper()

	var paramsRaw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		require.NoError(t, err)
		paramsRaw = b
	}

	reqBody, err := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  paramsRaw,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	var resp JSONRPCResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "2.0", resp.JSONRPC)

	return resp
}

func TestHandleInitialize(t *testing.T) {
	reg := newTestRegistry()
	srv := NewServer(reg)

	resp := doRPC(t, srv, "initialize", nil)

	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)

	result, ok := resp.Result.(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "2025-03-26", result["protocolVersion"])

	serverInfo, ok := result["serverInfo"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "PhantomStrike", serverInfo["name"])
	assert.Equal(t, "1.0.0", serverInfo["version"])

	caps, ok := result["capabilities"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, caps, "tools")
}

func TestHandlePing(t *testing.T) {
	reg := newTestRegistry()
	srv := NewServer(reg)

	resp := doRPC(t, srv, "ping", nil)

	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)

	result, ok := resp.Result.(map[string]any)
	require.True(t, ok)
	assert.Empty(t, result) // ping returns empty map
}

func TestHandleToolsList(t *testing.T) {
	reg := newTestRegistry(
		&tool.Definition{
			Name:             "nmap",
			ShortDescription: "Network scanner",
			Enabled:          true,
			Parameters: []tool.ParamDef{
				{Name: "target", Type: "string", Description: "Target host", Required: true},
				{Name: "ports", Type: "string", Description: "Port range", Required: false},
			},
		},
		&tool.Definition{
			Name:             "disabled-tool",
			ShortDescription: "Should not appear",
			Enabled:          false,
		},
	)
	srv := NewServer(reg)

	resp := doRPC(t, srv, "tools/list", nil)

	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)

	result, ok := resp.Result.(map[string]any)
	require.True(t, ok)

	toolsList, ok := result["tools"].([]any)
	require.True(t, ok)

	// Only enabled tools should appear
	assert.Len(t, toolsList, 1)

	toolMap, ok := toolsList[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "nmap", toolMap["name"])
	assert.Equal(t, "Network scanner", toolMap["description"])

	inputSchema, ok := toolMap["inputSchema"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "object", inputSchema["type"])

	props, ok := inputSchema["properties"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, props, "target")
	assert.Contains(t, props, "ports")

	required, ok := inputSchema["required"].([]any)
	require.True(t, ok)
	assert.Contains(t, required, "target")
}

func TestHandleToolsListEmpty(t *testing.T) {
	reg := newTestRegistry()
	srv := NewServer(reg)

	resp := doRPC(t, srv, "tools/list", nil)

	require.Nil(t, resp.Error)
	result, ok := resp.Result.(map[string]any)
	require.True(t, ok)

	// tools should be nil/empty when no tools registered
	tools := result["tools"]
	if tools != nil {
		toolsList, ok := tools.([]any)
		if ok {
			assert.Empty(t, toolsList)
		}
	}
}

func TestMethodNotFound(t *testing.T) {
	reg := newTestRegistry()
	srv := NewServer(reg)

	resp := doRPC(t, srv, "nonexistent/method", nil)

	require.NotNil(t, resp.Error)
	assert.Equal(t, -32601, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "Method not found")
}
