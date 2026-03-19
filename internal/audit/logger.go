package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ersinkoc/phantomstrike/internal/auth"
)

// Logger provides audit logging to the database.
type Logger struct {
	pool *pgxpool.Pool
}

// NewLogger creates a new audit logger.
func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{pool: pool}
}

// EnsureTable creates the audit_log table if it does not exist.
func (l *Logger) EnsureTable(ctx context.Context) error {
	_, err := l.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS audit_log (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id     UUID,
			user_id    UUID,
			action     TEXT NOT NULL,
			resource   TEXT NOT NULL,
			resource_id UUID,
			details    JSONB,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_audit_log_user    ON audit_log(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_log_action  ON audit_log(action);
		CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
	`)
	return err
}

// Log writes a single audit entry.
func (l *Logger) Log(ctx context.Context, action, resource string, resourceID *uuid.UUID, details map[string]any) error {
	var userID *uuid.UUID
	var orgID *uuid.UUID

	if claims := auth.GetClaims(ctx); claims != nil {
		uid := claims.UserID
		userID = &uid
		if claims.OrgID != uuid.Nil {
			oid := claims.OrgID
			orgID = &oid
		}
	}

	var detailsJSON []byte
	if details != nil {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshaling audit details: %w", err)
		}
	}

	_, err := l.pool.Exec(ctx,
		`INSERT INTO audit_log (org_id, user_id, action, resource, resource_id, details)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		orgID, userID, action, resource, resourceID, detailsJSON,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}

	return nil
}

// LogWithRequest writes an audit entry that includes IP address and user agent
// extracted from the HTTP request.
func (l *Logger) LogWithRequest(ctx context.Context, r *http.Request, action, resource string, resourceID *uuid.UUID, details map[string]any) error {
	var userID *uuid.UUID
	var orgID *uuid.UUID

	if claims := auth.GetClaims(ctx); claims != nil {
		uid := claims.UserID
		userID = &uid
		if claims.OrgID != uuid.Nil {
			oid := claims.OrgID
			orgID = &oid
		}
	}

	var detailsJSON []byte
	if details != nil {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshaling audit details: %w", err)
		}
	}

	ip := realIP(r)
	ua := r.UserAgent()

	_, err := l.pool.Exec(ctx,
		`INSERT INTO audit_log (org_id, user_id, action, resource, resource_id, details, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		orgID, userID, action, resource, resourceID, detailsJSON, ip, ua,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}

	return nil
}

// Middleware returns HTTP middleware that automatically logs mutation requests
// (POST, PUT, DELETE, PATCH) to the audit_log table.
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only audit mutation methods
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		default:
			next.ServeHTTP(w, r)
			return
		}

		// Capture response status
		sw := &auditStatusWriter{ResponseWriter: w, status: 200}
		start := time.Now()

		next.ServeHTTP(sw, r)

		// Log asynchronously to avoid adding latency
		go func() {
			action := r.Method + " " + r.URL.Path
			resource := resourceFromPath(r.URL.Path)

			var userID *uuid.UUID
			var orgID *uuid.UUID
			if claims := auth.GetClaims(r.Context()); claims != nil {
				uid := claims.UserID
				userID = &uid
				if claims.OrgID != uuid.Nil {
					oid := claims.OrgID
					orgID = &oid
				}
			}

			details, _ := json.Marshal(map[string]any{
				"status":      sw.status,
				"duration_ms": time.Since(start).Milliseconds(),
				"query":       r.URL.RawQuery,
			})

			ip := realIP(r)
			ua := r.UserAgent()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := l.pool.Exec(ctx,
				`INSERT INTO audit_log (org_id, user_id, action, resource, details, ip_address, user_agent)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				orgID, userID, action, resource, details, ip, ua,
			)
			if err != nil {
				slog.Error("failed to write audit log", "action", action, "error", err)
			}
		}()
	})
}

// auditStatusWriter wraps ResponseWriter to capture the status code.
type auditStatusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *auditStatusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditStatusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// resourceFromPath extracts the resource name from the URL path.
// For example, "/api/v1/missions/abc-123" returns "missions".
func resourceFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// Walk past api version prefix (e.g. "api", "v1")
	for i, p := range parts {
		if p == "v1" || p == "v2" {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	// Fallback: return the last non-UUID-looking segment
	for i := len(parts) - 1; i >= 0; i-- {
		if _, err := uuid.Parse(parts[i]); err != nil {
			return parts[i]
		}
	}
	return path
}

// realIP extracts the client IP from common proxy headers.
func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.SplitN(forwarded, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}
