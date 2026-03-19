package api

import "net/http"

func (h *Handler) handleListTools(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT name, category, enabled, source, avg_exec_time, success_rate, last_used FROM tool_registry ORDER BY category, name`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var tools []map[string]any
	for rows.Next() {
		var name, category, source string
		var enabled bool
		var avgTime *int
		var successRate *float64
		var lastUsed any
		if err := rows.Scan(&name, &category, &enabled, &source, &avgTime, &successRate, &lastUsed); err != nil {
			continue
		}
		tools = append(tools, map[string]any{
			"name": name, "category": category, "enabled": enabled, "source": source,
			"avg_exec_time": avgTime, "success_rate": successRate, "last_used": lastUsed,
		})
	}

	if tools == nil {
		tools = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

func (h *Handler) handleGetTool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var definition any
	var category, source string
	var enabled bool
	err := h.db.Pool.QueryRow(r.Context(),
		`SELECT definition, category, source, enabled FROM tool_registry WHERE name = $1`, name,
	).Scan(&definition, &category, &source, &enabled)
	if err != nil {
		writeError(w, http.StatusNotFound, "tool not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":       name,
		"category":   category,
		"source":     source,
		"enabled":    enabled,
		"definition": definition,
	})
}

func (h *Handler) handleToggleTool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	_, err := h.db.Pool.Exec(r.Context(),
		`UPDATE tool_registry SET enabled = NOT enabled, updated_at = NOW() WHERE name = $1`, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "toggle failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "toggled"})
}

func (h *Handler) handleToolCategories(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT category, COUNT(*) as count FROM tool_registry GROUP BY category ORDER BY category`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var categories []map[string]any
	for rows.Next() {
		var cat string
		var count int
		if err := rows.Scan(&cat, &count); err != nil {
			continue
		}
		categories = append(categories, map[string]any{"category": cat, "count": count})
	}

	writeJSON(w, http.StatusOK, map[string]any{"categories": categories})
}
