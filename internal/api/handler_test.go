package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"msg": "hello"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "hello", resp["msg"])
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "bad input")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "bad input", resp["error"])
}

func TestParseUUID(t *testing.T) {
	// Valid UUID
	id, err := parseUUID("550e8400-e29b-41d4-a716-446655440000")
	assert.NoError(t, err)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", id.String())

	// Invalid UUID
	_, err = parseUUID("not-a-uuid")
	assert.Error(t, err)
}

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, nil, nil)
	assert.NotNil(t, h)
}

func TestNewWSHub(t *testing.T) {
	hub := NewWSHub()
	assert.NotNil(t, hub)
	assert.NotNil(t, hub.connections)
	assert.Empty(t, hub.connections)
}

func TestDecodeJSON(t *testing.T) {
	body := `{"name":"test","value":42}`
	req := httptest.NewRequest("POST", "/test", strings.NewReader(body))

	var result struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	err := decodeJSON(req, &result)
	assert.NoError(t, err)
	assert.Equal(t, "test", result.Name)
	assert.Equal(t, 42, result.Value)
}
