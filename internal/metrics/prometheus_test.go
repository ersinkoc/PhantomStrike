package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.httpRequestsTotal)
	assert.NotNil(t, m.httpRequestDuration)
	assert.Equal(t, int64(0), m.toolExecutions)
	assert.Equal(t, int64(0), m.toolErrors)
	assert.Equal(t, int64(0), m.activeMissions)
}

func TestRecordHTTPRequest(t *testing.T) {
	m := NewMetrics()

	m.RecordHTTPRequest("GET", "/api/v1/missions", 200, 50*time.Millisecond)
	m.RecordHTTPRequest("GET", "/api/v1/missions", 200, 100*time.Millisecond)
	m.RecordHTTPRequest("POST", "/api/v1/missions", 201, 200*time.Millisecond)

	assert.Equal(t, int64(2), m.httpRequestsTotal["GET:/api/v1/missions:200"])
	assert.Equal(t, int64(1), m.httpRequestsTotal["POST:/api/v1/missions:201"])
	assert.Len(t, m.httpRequestDuration["GET:/api/v1/missions:200"], 2)
	assert.Len(t, m.httpRequestDuration["POST:/api/v1/missions:201"], 1)
}

func TestRecordToolExecution(t *testing.T) {
	m := NewMetrics()

	m.RecordToolExecution(true)
	m.RecordToolExecution(true)
	m.RecordToolExecution(false)

	assert.Equal(t, int64(3), m.toolExecutions)
	assert.Equal(t, int64(1), m.toolErrors)
}

func TestSetActiveMissions(t *testing.T) {
	m := NewMetrics()

	m.SetActiveMissions(5)
	assert.Equal(t, int64(5), m.activeMissions)

	m.SetActiveMissions(0)
	assert.Equal(t, int64(0), m.activeMissions)
}

func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()

	// Record some data
	m.RecordHTTPRequest("GET", "/health", 200, 10*time.Millisecond)
	m.RecordToolExecution(true)
	m.RecordToolExecution(false)
	m.SetActiveMissions(3)

	handler := m.Handler()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()

	// Verify Prometheus text exposition format
	assert.Contains(t, body, "# HELP http_requests_total Total HTTP requests")
	assert.Contains(t, body, "# TYPE http_requests_total counter")
	assert.Contains(t, body, "http_requests_total{")

	assert.Contains(t, body, "# HELP http_request_duration_seconds")
	assert.Contains(t, body, "# TYPE http_request_duration_seconds summary")
	assert.Contains(t, body, "http_request_duration_seconds_sum{")
	assert.Contains(t, body, "http_request_duration_seconds_count{")

	assert.Contains(t, body, "# HELP tool_executions_total Total tool executions")
	assert.Contains(t, body, "# TYPE tool_executions_total counter")
	assert.Contains(t, body, "tool_executions_total 2")

	assert.Contains(t, body, "# HELP tool_errors_total Total tool execution errors")
	assert.Contains(t, body, "# TYPE tool_errors_total counter")
	assert.Contains(t, body, "tool_errors_total 1")

	assert.Contains(t, body, "# HELP active_missions Number of currently active missions")
	assert.Contains(t, body, "# TYPE active_missions gauge")
	assert.Contains(t, body, "active_missions 3")

	// Verify content type header
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
}

func TestMetricsHandlerEmpty(t *testing.T) {
	m := NewMetrics()

	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "tool_executions_total 0")
	assert.Contains(t, body, "tool_errors_total 0")
	assert.Contains(t, body, "active_missions 0")
}

func TestParseKey(t *testing.T) {
	tests := []struct {
		key    string
		method string
		path   string
		status string
	}{
		{"GET:/api/v1/missions:200", "GET", "/api/v1/missions", "200"},
		{"POST:/api/v1/auth/login:401", "POST", "/api/v1/auth/login", "401"},
		{"DELETE:/api/v1/missions/{id}:204", "DELETE", "/api/v1/missions/{id}", "204"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			method, path, status := parseKey(tt.key)
			assert.Equal(t, tt.method, method)
			assert.Equal(t, tt.path, path)
			assert.Equal(t, tt.status, status)
		})
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]int64{
		"c": 3,
		"a": 1,
		"b": 2,
	}

	keys := sortedKeys(m)
	assert.Equal(t, []string{"a", "b", "c"}, keys)
}

func TestSortedKeysEmpty(t *testing.T) {
	m := map[string]int64{}
	keys := sortedKeys(m)
	assert.Empty(t, keys)
}
