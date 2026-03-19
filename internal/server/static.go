package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:static
var staticFS embed.FS

// staticHandler serves the embedded React SPA.
func staticHandler() http.Handler {
	// Try to get the "static" subdirectory
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// No embedded files — serve a simple redirect to frontend dev server
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend not embedded, use web dev server", http.StatusNotFound)
		})
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API and WS routes are handled by their own handlers
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/ws") ||
			strings.HasPrefix(r.URL.Path, "/health") ||
			strings.HasPrefix(r.URL.Path, "/metrics") {
			http.NotFound(w, r)
			return
		}

		// Try to serve static file
		// If not found, serve index.html for SPA routing
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		// Check if file exists
		if f, err := sub.Open(strings.TrimPrefix(path, "/")); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// Serve index.html for SPA fallback
		r.URL.Path = "/index.html"
		fileServer.ServeHTTP(w, r)
	})
}
