package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/agent"
	"github.com/ersinkoc/phantomstrike/internal/auth"
)

type missionRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Mode        string   `json:"mode"`
	Depth       string   `json:"depth"`
	Target      any      `json:"target"`
	Config      any      `json:"config"`
	Phases      []string `json:"phases"`
}

type missionTemplateRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Target      any      `json:"target"`
	Mode        string   `json:"mode"`
	Depth       string   `json:"depth"`
	Phases      []string `json:"phases"`
	Role        string   `json:"role"`
	Config      any      `json:"config"`
	IsBuiltin   bool     `json:"is_builtin"`
}

type missionTemplateResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Target      any       `json:"target"`
	Mode        string    `json:"mode"`
	Depth       string    `json:"depth"`
	Phases      []string  `json:"phases,omitempty"`
	Role        string    `json:"role,omitempty"`
	Config      any       `json:"config,omitempty"`
	IsBuiltin   bool      `json:"is_builtin"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type createMissionFromTemplateRequest struct {
	TemplateID  uuid.UUID `json:"template_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Target      any       `json:"target"` // optional override
}

type missionResponse struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description,omitempty"`
	Status       string     `json:"status"`
	Mode         string     `json:"mode"`
	Depth        string     `json:"depth"`
	Target       any        `json:"target"`
	Config       any        `json:"config,omitempty"`
	Phases       []string   `json:"phases,omitempty"`
	CurrentPhase *string    `json:"current_phase,omitempty"`
	Progress     int        `json:"progress"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (h *Handler) handleListMissions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, name, description, status, mode, depth, target, progress, current_phase, started_at, completed_at, created_at, updated_at
		 FROM missions ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list missions")
		return
	}
	defer rows.Close()

	var missions []missionResponse
	for rows.Next() {
		var m missionResponse
		if err := rows.Scan(&m.ID, &m.Name, &m.Description, &m.Status, &m.Mode, &m.Depth, &m.Target, &m.Progress, &m.CurrentPhase, &m.StartedAt, &m.CompletedAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			continue
		}
		missions = append(missions, m)
	}

	if missions == nil {
		missions = []missionResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"missions": missions,
		"total":    len(missions),
	})
}

func (h *Handler) handleCreateMission(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req missionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Target == nil {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	if req.Mode == "" {
		req.Mode = "autonomous"
	}
	if req.Depth == "" {
		req.Depth = "standard"
	}

	var id uuid.UUID
	err := h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO missions (name, description, mode, depth, target, config, phases, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		req.Name, req.Description, req.Mode, req.Depth, req.Target, req.Config, req.Phases, claims.UserID,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create mission")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":     id,
		"status": "created",
	})
}

func (h *Handler) handleGetMission(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	var m missionResponse
	err = h.db.Pool.QueryRow(r.Context(),
		`SELECT id, name, description, status, mode, depth, target, config, phases, progress, current_phase, started_at, completed_at, created_at, updated_at
		 FROM missions WHERE id = $1`, id,
	).Scan(&m.ID, &m.Name, &m.Description, &m.Status, &m.Mode, &m.Depth, &m.Target, &m.Config, &m.Phases, &m.Progress, &m.CurrentPhase, &m.StartedAt, &m.CompletedAt, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "mission not found")
		return
	}

	writeJSON(w, http.StatusOK, m)
}

func (h *Handler) handleUpdateMission(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	var req missionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	_, err = h.db.Pool.Exec(r.Context(),
		`UPDATE missions SET name = COALESCE(NULLIF($1, ''), name), description = COALESCE(NULLIF($2, ''), description), updated_at = NOW() WHERE id = $3`,
		req.Name, req.Description, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) handleDeleteMission(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	_, err = h.db.Pool.Exec(r.Context(), "DELETE FROM missions WHERE id = $1", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) handleStartMission(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// Get mission details first
	var mission struct {
		Target any      `json:"target"`
		Phases []string `json:"phases"`
		Mode   string   `json:"mode"`
	}
	err = h.db.Pool.QueryRow(r.Context(),
		`SELECT target, phases, mode FROM missions WHERE id = $1`, id,
	).Scan(&mission.Target, &mission.Phases, &mission.Mode)
	if err != nil {
		writeError(w, http.StatusNotFound, "mission not found")
		return
	}

	now := time.Now()
	_, err = h.db.Pool.Exec(r.Context(),
		`UPDATE missions SET status = 'running', started_at = $1, updated_at = $1 WHERE id = $2 AND status = 'created'`,
		now, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start mission")
		return
	}

	// Trigger agent swarm to begin mission execution asynchronously
	go func() {
		ctx := context.Background()

		// Create conversation for this mission so frontend can see activity
		var convID uuid.UUID
		_ = h.db.Pool.QueryRow(ctx,
			`INSERT INTO conversations (mission_id, title, agent_type, status)
			 VALUES ($1, 'Mission Execution', 'executor', 'active') RETURNING id`,
			id,
		).Scan(&convID)

		// Send initial system message with target info
		targetStr := fmt.Sprintf("%v", mission.Target)
		h.db.Pool.Exec(ctx,
			`INSERT INTO messages (conversation_id, role, content)
			 VALUES ($1, 'assistant', $2)`,
			convID, fmt.Sprintf("Starting autonomous security scan.\nTarget: %s\nMode: %s", targetStr, mission.Mode),
		)

		// Create event channel for this mission
		events := make(chan agent.SwarmEvent, 100)

		// Start event broadcaster — save events as messages too
		go func() {
			for event := range events {
				// Broadcast to WebSocket clients
				h.hub.Broadcast(id, WSEvent{
					Type: event.Type,
					Data: map[string]any{
						"agent": event.Agent,
						"data":  event.Data,
					},
				})

				// Save tool events as messages in the conversation
				if convID != uuid.Nil {
					switch event.Type {
					case "thinking":
						if thought, ok := event.Data.(map[string]any)["thought"]; ok {
							h.db.Pool.Exec(ctx,
								`INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)`,
								convID, thought)
						}
					case "tool_start":
						if data, ok := event.Data.(map[string]any); ok {
							h.db.Pool.Exec(ctx,
								`INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)`,
								convID, fmt.Sprintf("Running tool: %v with params: %v", data["tool"], data["params"]))
						}
					case "tool_complete":
						if data, ok := event.Data.(map[string]any); ok {
							h.db.Pool.Exec(ctx,
								`INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'tool', $2)`,
								convID, fmt.Sprintf("Tool %v completed (exit %v, %vms)", data["tool"], data["exit_code"], data["duration_ms"]))
						}
					}
				}
			}
		}()

		// Convert phases
		var phases []agent.Phase
		for _, p := range mission.Phases {
			phases = append(phases, agent.Phase(p))
		}
		if len(phases) == 0 {
			phases = []agent.Phase{agent.PhaseRecon, agent.PhaseScanning, agent.PhaseExploit, agent.PhaseReporting}
		}

		// Run the mission
		if err := h.swarm.RunMission(ctx, id, mission.Target, phases, events); err != nil {
			slog.Error("mission failed", "mission_id", id, "error", err)
			// Update mission status to failed
			h.db.Pool.Exec(ctx,
				`UPDATE missions SET status = 'failed', updated_at = NOW() WHERE id = $1`,
				id,
			)
		} else {
			// Update mission status to completed
			h.db.Pool.Exec(ctx,
				`UPDATE missions SET status = 'completed', completed_at = NOW(), updated_at = NOW() WHERE id = $1`,
				id,
			)
		}

		close(events)
	}()

	writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
}

func (h *Handler) handlePauseMission(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	_, _ = h.db.Pool.Exec(r.Context(),
		`UPDATE missions SET status = 'paused', updated_at = NOW() WHERE id = $1`, id)

	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (h *Handler) handleCancelMission(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	_, _ = h.db.Pool.Exec(r.Context(),
		`UPDATE missions SET status = 'cancelled', updated_at = NOW() WHERE id = $1`, id)

	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (h *Handler) handleGetAttackChain(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// Get nodes
	nodeRows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, node_type, label, data, severity, phase FROM attack_chain_nodes WHERE mission_id = $1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get chain")
		return
	}
	defer nodeRows.Close()

	var nodes []map[string]any
	for nodeRows.Next() {
		var nID uuid.UUID
		var nodeType, label string
		var data any
		var severity, phase *string
		if err := nodeRows.Scan(&nID, &nodeType, &label, &data, &severity, &phase); err != nil {
			continue
		}
		nodes = append(nodes, map[string]any{
			"id": nID, "type": nodeType, "label": label, "data": data, "severity": severity, "phase": phase,
		})
	}

	// Get edges
	edgeRows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, source_id, target_id, edge_type, label FROM attack_chain_edges WHERE mission_id = $1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get edges")
		return
	}
	defer edgeRows.Close()

	var edges []map[string]any
	for edgeRows.Next() {
		var eID, srcID, tgtID uuid.UUID
		var edgeType string
		var label *string
		if err := edgeRows.Scan(&eID, &srcID, &tgtID, &edgeType, &label); err != nil {
			continue
		}
		edges = append(edges, map[string]any{
			"id": eID, "source": srcID, "target": tgtID, "type": edgeType, "label": label,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

func (h *Handler) handleGetMissionTools(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, tool_name, parameters, status, execution_mode, container_id,
			stdout, stderr, exit_code, duration_ms, started_at, completed_at, created_at
		 FROM tool_executions WHERE mission_id = $1 ORDER BY created_at DESC`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var executions []map[string]any
	for rows.Next() {
		var execID uuid.UUID
		var toolName, status, executionMode string
		var parameters any
		var containerID, stdout, stderr *string
		var exitCode, durationMs *int
		var startedAt, completedAt interface{}
		var createdAt time.Time
		if err := rows.Scan(&execID, &toolName, &parameters, &status, &executionMode, &containerID,
			&stdout, &stderr, &exitCode, &durationMs, &startedAt, &completedAt, &createdAt); err != nil {
			continue
		}
		executions = append(executions, map[string]any{
			"id":             execID,
			"tool_name":      toolName,
			"parameters":     parameters,
			"status":         status,
			"execution_mode": executionMode,
			"container_id":   containerID,
			"stdout":         stdout,
			"stderr":         stderr,
			"exit_code":      exitCode,
			"duration_ms":    durationMs,
			"started_at":     startedAt,
			"completed_at":   completedAt,
			"created_at":     createdAt,
		})
	}

	if executions == nil {
		executions = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"tool_executions": executions})
}

func (h *Handler) handleGetMissionReports(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, format, title, status, file_path, file_size, created_at
		 FROM reports WHERE mission_id = $1 ORDER BY created_at DESC`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var reports []map[string]any
	for rows.Next() {
		var reportID string
		var format, title, status string
		var filePath interface{}
		var fileSize int64
		var createdAt string
		if err := rows.Scan(&reportID, &format, &title, &status, &filePath, &fileSize, &createdAt); err != nil {
			continue
		}
		reports = append(reports, map[string]any{
			"id":        reportID,
			"format":    format,
			"title":     title,
			"status":    status,
			"file_path": filePath,
			"file_size": fileSize,
			"created_at": createdAt,
		})
	}

	if reports == nil {
		reports = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
}

func (h *Handler) handleGetMissionVulns(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, title, severity, cvss_score, status, target, found_by, created_at
		 FROM vulnerabilities WHERE mission_id = $1 ORDER BY created_at DESC`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var vulns []map[string]any
	for rows.Next() {
		var vID uuid.UUID
		var title, severity, status string
		var cvssScore *float64
		var target, foundBy *string
		var createdAt time.Time
		if err := rows.Scan(&vID, &title, &severity, &cvssScore, &status, &target, &foundBy, &createdAt); err != nil {
			continue
		}
		vulns = append(vulns, map[string]any{
			"id": vID, "title": title, "severity": severity, "cvss_score": cvssScore,
			"status": status, "target": target, "found_by": foundBy, "created_at": createdAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns})
}

// --- Mission Templates ---

func (h *Handler) handleListMissionTemplates(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, name, description, target, mode, depth, phases, role, config, is_builtin, created_at, updated_at
		 FROM mission_templates ORDER BY name`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list mission templates")
		return
	}
	defer rows.Close()

	var templates []missionTemplateResponse
	for rows.Next() {
		var t missionTemplateResponse
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Target, &t.Mode, &t.Depth, &t.Phases, &t.Role, &t.Config, &t.IsBuiltin, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		templates = append(templates, t)
	}

	if templates == nil {
		templates = []missionTemplateResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"templates": templates,
		"total":     len(templates),
	})
}

func (h *Handler) handleCreateMissionTemplate(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req missionTemplateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Mode == "" {
		req.Mode = "autonomous"
	}
	if req.Depth == "" {
		req.Depth = "standard"
	}
	if req.Target == nil {
		req.Target = map[string]any{}
	}
	if req.Phases == nil {
		req.Phases = []string{}
	}

	var id uuid.UUID
	err := h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO mission_templates (name, description, target, mode, depth, phases, role, config, is_builtin, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		req.Name, req.Description, req.Target, req.Mode, req.Depth, req.Phases, req.Role, req.Config, req.IsBuiltin, claims.UserID,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create mission template")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":     id,
		"status": "created",
	})
}

func (h *Handler) handleDeleteMissionTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template ID")
		return
	}

	tag, err := h.db.Pool.Exec(r.Context(),
		`DELETE FROM mission_templates WHERE id = $1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete mission template")
		return
	}

	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "mission template not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) handleCreateMissionFromTemplate(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req createMissionFromTemplateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TemplateID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "template_id is required")
		return
	}

	// Load template
	var tmpl missionTemplateResponse
	err := h.db.Pool.QueryRow(r.Context(),
		`SELECT id, name, description, target, mode, depth, phases, role, config, is_builtin, created_at, updated_at
		 FROM mission_templates WHERE id = $1`, req.TemplateID,
	).Scan(&tmpl.ID, &tmpl.Name, &tmpl.Description, &tmpl.Target, &tmpl.Mode, &tmpl.Depth, &tmpl.Phases, &tmpl.Role, &tmpl.Config, &tmpl.IsBuiltin, &tmpl.CreatedAt, &tmpl.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "mission template not found")
		return
	}

	// Use template values, allow overrides
	name := tmpl.Name
	if req.Name != "" {
		name = req.Name
	}
	description := tmpl.Description
	if req.Description != "" {
		description = req.Description
	}
	target := tmpl.Target
	if req.Target != nil {
		target = req.Target
	}

	var id uuid.UUID
	err = h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO missions (name, description, mode, depth, target, config, phases, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		name, description, tmpl.Mode, tmpl.Depth, target, tmpl.Config, tmpl.Phases, claims.UserID,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create mission from template")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          id,
		"template_id": req.TemplateID,
		"status":      "created",
	})
}
