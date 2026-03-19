package metrics

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/pkg/version"
)

var startTime = time.Now()

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status    string         `json:"status"`
	Version   string         `json:"version"`
	Commit    string         `json:"commit"`
	Uptime    string         `json:"uptime"`
	GoVersion string         `json:"go_version"`
	Memory    MemoryStats    `json:"memory"`
}

// MemoryStats contains memory usage information.
type MemoryStats struct {
	Alloc      uint64 `json:"alloc_mb"`
	TotalAlloc uint64 `json:"total_alloc_mb"`
	Sys        uint64 `json:"sys_mb"`
	NumGC      uint32 `json:"num_gc"`
	Goroutines int    `json:"goroutines"`
}

// HealthHandler returns a health check HTTP handler.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		resp := HealthResponse{
			Status:    "ok",
			Version:   version.Version,
			Commit:    version.Commit,
			Uptime:    time.Since(startTime).Truncate(time.Second).String(),
			GoVersion: runtime.Version(),
			Memory: MemoryStats{
				Alloc:      m.Alloc / 1024 / 1024,
				TotalAlloc: m.TotalAlloc / 1024 / 1024,
				Sys:        m.Sys / 1024 / 1024,
				NumGC:      m.NumGC,
				Goroutines: runtime.NumGoroutine(),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
