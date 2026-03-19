package audit

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResourceFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "standard v1 API path",
			path: "/api/v1/missions/abc-123",
			want: "missions",
		},
		{
			name: "v1 API path without ID",
			path: "/api/v1/tools",
			want: "tools",
		},
		{
			name: "v2 API path",
			path: "/api/v2/vulnerabilities/some-id",
			want: "vulnerabilities",
		},
		{
			name: "no version prefix fallback",
			path: "/health",
			want: "health",
		},
		{
			name: "UUID-only last segment falls back",
			path: "/api/v1/missions/550e8400-e29b-41d4-a716-446655440000",
			want: "missions",
		},
		{
			name: "root path",
			path: "/",
			want: "",
		},
		{
			name: "deeply nested path with version",
			path: "/api/v1/reports/export/pdf",
			want: "reports",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resourceFromPath(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRealIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "X-Real-IP header takes priority",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Real-IP": "203.0.113.50"},
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For with single IP",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.10"},
			want:       "198.51.100.10",
		},
		{
			name:       "X-Forwarded-For with multiple IPs returns first",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.10, 10.0.0.1, 172.16.0.1"},
			want:       "198.51.100.10",
		},
		{
			name:       "falls back to RemoteAddr host part",
			remoteAddr: "192.168.1.100:8080",
			headers:    map[string]string{},
			want:       "192.168.1.100",
		},
		{
			name:       "X-Real-IP takes priority over X-Forwarded-For",
			remoteAddr: "127.0.0.1:54321",
			headers: map[string]string{
				"X-Real-IP":       "203.0.113.50",
				"X-Forwarded-For": "198.51.100.10",
			},
			want: "203.0.113.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			got := realIP(r)
			assert.Equal(t, tt.want, got)
		})
	}
}
