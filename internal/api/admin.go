package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// handleListUsers returns all users (admin only).
func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	// Count total
	var total int64
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM users").Scan(&total)

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, email, name, role, avatar_url, created_at, last_login
		 FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var users []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var email, name, role string
		var avatarURL *string
		var createdAt time.Time
		var lastLogin *time.Time
		if err := rows.Scan(&id, &email, &name, &role, &avatarURL, &createdAt, &lastLogin); err != nil {
			continue
		}
		users = append(users, map[string]any{
			"id":         id,
			"email":      email,
			"name":       name,
			"role":       role,
			"avatar_url": avatarURL,
			"created_at": createdAt,
			"last_login": lastLogin,
		})
	}

	if users == nil {
		users = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"users": users,
		"total": total,
	})
}

// handleGetAuditLog queries the audit_log table with pagination and filters.
func (h *Handler) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	action := r.URL.Query().Get("action")
	resource := r.URL.Query().Get("resource")
	userID := r.URL.Query().Get("user_id")

	query := `SELECT id, org_id, user_id, action, resource, resource_id, details, ip_address, user_agent, created_at
	          FROM audit_log WHERE 1=1`
	args := []any{}
	argIdx := 1

	if action != "" {
		query += ` AND action ILIKE $` + strconv.Itoa(argIdx)
		args = append(args, "%"+action+"%")
		argIdx++
	}
	if resource != "" {
		query += ` AND resource = $` + strconv.Itoa(argIdx)
		args = append(args, resource)
		argIdx++
	}
	if userID != "" {
		uid, err := uuid.Parse(userID)
		if err == nil {
			query += ` AND user_id = $` + strconv.Itoa(argIdx)
			args = append(args, uid)
			argIdx++
		}
	}

	query += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var entries []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var orgID, rUserID, resourceID *uuid.UUID
		var actionVal, resourceVal string
		var details any
		var ipAddress, userAgent *string
		var createdAt time.Time
		if err := rows.Scan(&id, &orgID, &rUserID, &actionVal, &resourceVal, &resourceID, &details, &ipAddress, &userAgent, &createdAt); err != nil {
			continue
		}
		entries = append(entries, map[string]any{
			"id":          id,
			"org_id":      orgID,
			"user_id":     rUserID,
			"action":      actionVal,
			"resource":    resourceVal,
			"resource_id": resourceID,
			"details":     details,
			"ip_address":  ipAddress,
			"user_agent":  userAgent,
			"created_at":  createdAt,
		})
	}

	if entries == nil {
		entries = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"audit_log": entries})
}
