package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyMiddleware(t *testing.T) {
	// Test individual middleware wrapping, not applyMiddleware which needs real dependencies
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Chain middleware manually (same order as applyMiddleware)
	handler := recoveryMiddleware(requestIDMiddleware(loggingMiddleware(inner)))
	assert.NotNil(t, handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestIDMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request ID is in context
		id := GetRequestID(r.Context())
		assert.NotEmpty(t, id)
		w.WriteHeader(http.StatusOK)
	})

	handler := requestIDMiddleware(inner)

	// Without X-Request-ID header — should generate one
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

	// With X-Request-ID header — should use provided value
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Request-ID", "custom-id-123")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	assert.Equal(t, "custom-id-123", w2.Header().Get("X-Request-ID"))
}

func TestLoggingMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	handler := loggingMiddleware(inner)
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRecoveryMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := recoveryMiddleware(inner)
	req := httptest.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()

	// Should not panic — recovery middleware catches it
	assert.NotPanics(t, func() {
		handler.ServeHTTP(w, req)
	})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCORSMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allowed origin", func(t *testing.T) {
		handler := corsMiddleware(inner, []string{"http://localhost:3000"})
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("disallowed origin", func(t *testing.T) {
		handler := corsMiddleware(inner, []string{"http://localhost:3000"})
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://evil.com")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("wildcard origin", func(t *testing.T) {
		handler := corsMiddleware(inner, []string{"*"})
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://any-origin.com")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, "http://any-origin.com", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("preflight OPTIONS", func(t *testing.T) {
		handler := corsMiddleware(inner, []string{"*"})
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestStatusWriter(t *testing.T) {
	w := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: w, status: 200}

	// Write without explicit WriteHeader — should still work
	n, err := sw.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.True(t, sw.wroteHeader)

	// WriteHeader should only set once
	sw2 := &statusWriter{ResponseWriter: httptest.NewRecorder(), status: 200}
	sw2.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, sw2.status)
	sw2.WriteHeader(http.StatusOK) // should be ignored
	assert.Equal(t, http.StatusNotFound, sw2.status)
}

func TestGetRequestID(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GetRequestID(r.Context())
		w.Write([]byte(id))
	})

	handler := requestIDMiddleware(inner)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "test-req-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, "test-req-id", w.Body.String())
}

func TestRealIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		addr     string
		expected string
	}{
		{
			name:     "X-Real-IP header",
			headers:  map[string]string{"X-Real-IP": "1.2.3.4"},
			addr:     "127.0.0.1:8080",
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For header",
			headers:  map[string]string{"X-Forwarded-For": "5.6.7.8, 9.10.11.12"},
			addr:     "127.0.0.1:8080",
			expected: "5.6.7.8",
		},
		{
			name:     "RemoteAddr fallback",
			headers:  map[string]string{},
			addr:     "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.addr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tt.expected, RealIP(req))
		})
	}
}
