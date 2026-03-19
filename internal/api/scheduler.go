package api

import (
	"encoding/json"
	"net/http"
)

// handleListScheduler returns scheduled jobs
func (h *Handler) handleListScheduler(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, name, description, cron_expr, enabled, run_count, last_run, next_run, created_at
		 FROM scheduled_jobs ORDER BY created_at DESC`,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var jobs []map[string]interface{}
	for rows.Next() {
		var id, name, description, cronExpr string
		var enabled bool
		var runCount int
		var lastRun, nextRun interface{}
		var createdAt string
		if err := rows.Scan(&id, &name, &description, &cronExpr, &enabled, &runCount, &lastRun, &nextRun, &createdAt); err != nil {
			continue
		}
		jobs = append(jobs, map[string]interface{}{
			"id":          id,
			"name":        name,
			"description": description,
			"cron_expr":   cronExpr,
			"enabled":     enabled,
			"run_count":   runCount,
			"last_run":    lastRun,
			"next_run":    nextRun,
			"created_at":  createdAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"jobs": jobs})
}

// handleCreateScheduler creates a new scheduled job
func (h *Handler) handleCreateScheduler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string          `json:"name"`
		Description     string          `json:"description"`
		CronExpr        string          `json:"cron_expr"`
		MissionTemplate json.RawMessage `json:"mission_template"`
		Enabled         *bool           `json:"enabled"`
	}

	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.CronExpr == "" {
		writeError(w, http.StatusBadRequest, "cron_expr is required")
		return
	}
	if len(req.MissionTemplate) == 0 {
		writeError(w, http.StatusBadRequest, "mission_template is required")
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var id string
	err := h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO scheduled_jobs (name, description, cron_expr, mission_template, enabled)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.Name, req.Description, req.CronExpr, req.MissionTemplate, enabled,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create scheduled job")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":     id,
		"status": "created",
	})
}

// handleUpdateScheduler updates an existing scheduled job
func (h *Handler) handleUpdateScheduler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "job ID required")
		return
	}

	var req struct {
		Name            *string          `json:"name"`
		Description     *string          `json:"description"`
		CronExpr        *string          `json:"cron_expr"`
		MissionTemplate *json.RawMessage `json:"mission_template"`
		Enabled         *bool            `json:"enabled"`
	}

	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build dynamic update using COALESCE pattern
	_, err := h.db.Pool.Exec(r.Context(),
		`UPDATE scheduled_jobs SET
			name = COALESCE($1, name),
			description = COALESCE($2, description),
			cron_expr = COALESCE($3, cron_expr),
			mission_template = COALESCE($4, mission_template),
			enabled = COALESCE($5, enabled)
		 WHERE id = $6`,
		req.Name, req.Description, req.CronExpr, req.MissionTemplate, req.Enabled, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// handleTriggerScheduler triggers a job immediately
func (h *Handler) handleTriggerScheduler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "job ID required")
		return
	}

	// Update last_run to now
	_, err := h.db.Pool.Exec(r.Context(),
		"UPDATE scheduled_jobs SET last_run = NOW(), run_count = run_count + 1 WHERE id = $1", id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "trigger failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "triggered"})
}

// handleDeleteScheduler deletes a scheduled job
func (h *Handler) handleDeleteScheduler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "job ID required")
		return
	}

	_, err := h.db.Pool.Exec(r.Context(), "DELETE FROM scheduled_jobs WHERE id = $1", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
