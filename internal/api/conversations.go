package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

func (h *Handler) handleListConversations(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, title, agent_type, status, created_at FROM conversations WHERE mission_id = $1 ORDER BY created_at`, missionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var conversations []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var title, agentType, status *string
		var createdAt time.Time
		if err := rows.Scan(&id, &title, &agentType, &status, &createdAt); err != nil {
			continue
		}
		conversations = append(conversations, map[string]any{
			"id": id, "title": title, "agent_type": agentType, "status": status, "created_at": createdAt,
		})
	}

	if conversations == nil {
		conversations = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"conversations": conversations})
}

func (h *Handler) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, role, content, tool_calls, tool_call_id, model, provider, created_at
		 FROM messages WHERE conversation_id = $1 ORDER BY created_at LIMIT $2 OFFSET $3`,
		convID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var messages []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var role string
		var content, toolCallID, model, provider *string
		var toolCalls any
		var createdAt time.Time
		if err := rows.Scan(&id, &role, &content, &toolCalls, &toolCallID, &model, &provider, &createdAt); err != nil {
			continue
		}
		messages = append(messages, map[string]any{
			"id": id, "role": role, "content": content, "tool_calls": toolCalls,
			"tool_call_id": toolCallID, "model": model, "provider": provider, "created_at": createdAt,
		})
	}

	if messages == nil {
		messages = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"messages": messages})
}

func (h *Handler) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}

	var req struct {
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}

	// Store user message
	var msgID uuid.UUID
	err = h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'user', $2) RETURNING id`,
		convID, req.Content,
	).Scan(&msgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save message")
		return
	}

	// TODO: Trigger agent processing via the swarm coordinator

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":   msgID,
		"role": "user",
		"content": req.Content,
		"status":  "processing",
	})
}
