package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Metrics collects Prometheus-compatible application metrics.
type Metrics struct {
	httpRequestsTotal   map[string]int64
	httpRequestDuration map[string][]float64
	toolExecutions      int64
	toolErrors          int64
	activeMissions      int64
	mu                  sync.Mutex
}

// NewMetrics creates a new Metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{
		httpRequestsTotal:   make(map[string]int64),
		httpRequestDuration: make(map[string][]float64),
	}
}

// RecordHTTPRequest records an HTTP request with its method, path, status, and duration.
func (m *Metrics) RecordHTTPRequest(method, path string, status int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%d", method, path, status)
	m.httpRequestsTotal[key]++
	m.httpRequestDuration[key] = append(m.httpRequestDuration[key], duration.Seconds())
}

// RecordToolExecution records a tool execution result.
func (m *Metrics) RecordToolExecution(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.toolExecutions++
	if !success {
		m.toolErrors++
	}
}

// SetActiveMissions sets the current number of active missions.
func (m *Metrics) SetActiveMissions(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activeMissions = count
}

// Handler returns an http.HandlerFunc that outputs metrics in Prometheus text exposition format.
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// http_requests_total
		fmt.Fprintln(w, "# HELP http_requests_total Total HTTP requests")
		fmt.Fprintln(w, "# TYPE http_requests_total counter")
		keys := sortedKeys(m.httpRequestsTotal)
		for _, key := range keys {
			method, path, status := parseKey(key)
			fmt.Fprintf(w, "http_requests_total{method=%q,path=%q,status=%q} %d\n",
				method, path, status, m.httpRequestsTotal[key])
		}

		// http_request_duration_seconds
		fmt.Fprintln(w, "# HELP http_request_duration_seconds HTTP request latencies in seconds")
		fmt.Fprintln(w, "# TYPE http_request_duration_seconds summary")
		durKeys := sortedKeys(m.httpRequestDuration)
		for _, key := range durKeys {
			method, path, status := parseKey(key)
			durations := m.httpRequestDuration[key]
			sum := 0.0
			for _, d := range durations {
				sum += d
			}
			fmt.Fprintf(w, "http_request_duration_seconds_sum{method=%q,path=%q,status=%q} %.6f\n",
				method, path, status, sum)
			fmt.Fprintf(w, "http_request_duration_seconds_count{method=%q,path=%q,status=%q} %d\n",
				method, path, status, len(durations))
		}

		// tool_executions_total
		fmt.Fprintln(w, "# HELP tool_executions_total Total tool executions")
		fmt.Fprintln(w, "# TYPE tool_executions_total counter")
		fmt.Fprintf(w, "tool_executions_total %d\n", m.toolExecutions)

		// tool_errors_total
		fmt.Fprintln(w, "# HELP tool_errors_total Total tool execution errors")
		fmt.Fprintln(w, "# TYPE tool_errors_total counter")
		fmt.Fprintf(w, "tool_errors_total %d\n", m.toolErrors)

		// active_missions
		fmt.Fprintln(w, "# HELP active_missions Number of currently active missions")
		fmt.Fprintln(w, "# TYPE active_missions gauge")
		fmt.Fprintf(w, "active_missions %d\n", m.activeMissions)
	}
}

// parseKey splits a "method:path:status" key into its components.
func parseKey(key string) (method, path, status string) {
	// Find the first colon (method)
	i := 0
	for i < len(key) && key[i] != ':' {
		i++
	}
	method = key[:i]

	// Find the last colon (status)
	j := len(key) - 1
	for j > i && key[j] != ':' {
		j--
	}
	path = key[i+1 : j]
	status = key[j+1:]
	return
}

// sortedKeys returns sorted keys from a map.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
