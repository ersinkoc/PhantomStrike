package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/provider"
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

	// Trigger AI processing asynchronously
	go h.processConversationMessage(convID, msgID, req.Content)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":      msgID,
		"role":    "user",
		"content": req.Content,
		"status":  "processing",
	})
}

// processConversationMessage triggers AI processing for a user message in a conversation.
// It looks up the conversation context, builds chat history, calls the LLM, optionally
// executes tool calls, saves the assistant response, and broadcasts it via WebSocket.
func (h *Handler) processConversationMessage(convID, userMsgID uuid.UUID, userContent string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("PANIC in processConversationMessage", "error", r, "conversation_id", convID)
		}
	}()

	slog.Info("AI processing started", "conversation_id", convID, "user_msg", userContent[:min(len(userContent), 100)])

	// Use a background context since the HTTP request context may already be cancelled
	ctx := context.Background()

	// 1. Look up conversation details (mission, agent_type)
	var missionID uuid.UUID
	var agentType *string
	err := h.db.Pool.QueryRow(ctx,
		`SELECT mission_id, agent_type FROM conversations WHERE id = $1`, convID,
	).Scan(&missionID, &agentType)
	if err != nil {
		slog.Error("failed to look up conversation for AI processing", "conversation_id", convID, "error", err)
		return
	}

	// 2. Get mission context for system prompt
	var missionName, missionDesc string
	err = h.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(name, ''), COALESCE(description, '') FROM missions WHERE id = $1`, missionID,
	).Scan(&missionName, &missionDesc)
	if err != nil {
		slog.Warn("failed to look up mission for AI processing", "mission_id", missionID, "error", err)
		// Continue without mission context
	}

	// 3. Build chat history from existing messages
	rows, err := h.db.Pool.Query(ctx,
		`SELECT role, content, tool_calls, tool_call_id FROM messages
		 WHERE conversation_id = $1 ORDER BY created_at LIMIT 50`, convID,
	)
	if err != nil {
		slog.Error("failed to load message history", "conversation_id", convID, "error", err)
		return
	}
	defer rows.Close()

	var messages []provider.Message
	for rows.Next() {
		var role string
		var content, toolCallID *string
		var toolCallsJSON []byte
		if err := rows.Scan(&role, &content, &toolCallsJSON, &toolCallID); err != nil {
			continue
		}
		msg := provider.Message{Role: role}
		if content != nil {
			msg.Content = *content
		}
		if toolCallID != nil {
			msg.ToolCallID = *toolCallID
		}
		if len(toolCallsJSON) > 0 {
			var tcs []provider.ToolCall
			if json.Unmarshal(toolCallsJSON, &tcs) == nil {
				msg.ToolCalls = tcs
			}
		}
		messages = append(messages, msg)
	}

	// 4. Build system prompt
	systemPrompt := fmt.Sprintf(
		`You are PhantomStrike, an AI-powered security assessment assistant.
Mission: %s
Description: %s

Help the user with their security testing tasks. You can use available tools to run scans,
analyze results, and provide recommendations. Be precise, thorough, and security-focused.`,
		missionName, missionDesc,
	)

	// 5. Get provider from the swarm's router and build tool definitions
	providerRouter := h.swarm.GetRouter()
	if providerRouter == nil {
		slog.Error("provider router not available for AI processing")
		return
	}

	// Build available tools list — limit to core tools to avoid overloading local LLMs.
	coreTools := map[string]bool{
		"nmap": true, "nuclei": true, "httpx": true, "amass": true,
		"gobuster": true, "testssl": true, "hydra": true, "subfinder": true,
		"naabu": true, "feroxbuster": true, "nikto": true, "sqlmap": true,
		"ffuf": true, "dirsearch": true, "wpscan": true,
	}
	var tools []provider.Tool
	if h.registry != nil {
		for _, def := range h.registry.List() {
			if !def.Enabled || !coreTools[def.Name] {
				continue
			}
			properties := make(map[string]any)
			var required []string
			for _, p := range def.Parameters {
				prop := map[string]any{
					"type":        p.Type,
					"description": p.Description,
				}
				if len(p.Enum) > 0 {
					prop["enum"] = p.Enum
				}
				properties[p.Name] = prop
				if p.Required {
					required = append(required, p.Name)
				}
			}
			tools = append(tools, provider.Tool{
				Name:        def.Name,
				Description: def.ShortDescription,
				InputSchema: map[string]any{
					"type":       "object",
					"properties": properties,
					"required":   required,
				},
			})
		}
	}

	resp, err := providerRouter.ChatCompletion(ctx, provider.ChatRequest{
		System:    systemPrompt,
		Messages:  messages,
		Tools:     tools,
		MaxTokens: 4096,
	})
	if err != nil {
		slog.Error("AI chat completion failed", "conversation_id", convID, "error", err)
		return
	}

	// 6. If there are tool calls, execute them
	assistantContent := resp.Content
	if len(resp.ToolCalls) > 0 {
		executor := h.swarm.GetExecutor()
		if executor != nil {
			for _, tc := range resp.ToolCalls {
				result, err := executor.Execute(ctx, tc.Name, tc.Input, &missionID, &convID)
				if err != nil {
					assistantContent += fmt.Sprintf("\n\n[Tool %s failed: %v]", tc.Name, err)
				} else {
					assistantContent += fmt.Sprintf("\n\n[Tool %s result (exit %d):\n%s]", tc.Name, result.ExitCode, result.Stdout)
				}
			}
		}
	}

	// 7. Save the assistant response as a new message
	var assistantMsgID uuid.UUID
	var modelName, providerName *string
	if resp.Model != "" {
		modelName = &resp.Model
	}
	err = h.db.Pool.QueryRow(ctx,
		`INSERT INTO messages (conversation_id, role, content, model, provider)
		 VALUES ($1, 'assistant', $2, $3, $4) RETURNING id`,
		convID, assistantContent, modelName, providerName,
	).Scan(&assistantMsgID)
	if err != nil {
		slog.Error("failed to save assistant message", "conversation_id", convID, "error", err)
		return
	}

	// 8. Broadcast the response via WebSocket hub
	if h.hub != nil {
		h.hub.Broadcast(missionID, WSEvent{
			Type: "message",
			Data: map[string]any{
				"id":              assistantMsgID,
				"conversation_id": convID,
				"role":            "assistant",
				"content":         assistantContent,
				"model":           modelName,
			},
		})
	}

	slog.Info("AI response saved and broadcast",
		"conversation_id", convID,
		"assistant_msg_id", assistantMsgID,
		"content_length", len(assistantContent),
	)
}
