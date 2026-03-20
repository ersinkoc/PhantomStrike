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
	var missionTarget any
	err = h.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(name, ''), COALESCE(description, ''), target FROM missions WHERE id = $1`, missionID,
	).Scan(&missionName, &missionDesc, &missionTarget)
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
	targetStr := fmt.Sprintf("%v", missionTarget)
	systemPrompt := fmt.Sprintf(
		`You are PhantomStrike, an autonomous AI security testing assistant.

MISSION: %s
DESCRIPTION: %s
TARGET: %s

CRITICAL: Always use the exact target above. Never use example.com, target.com, or made-up IPs.
When calling tools, ALWAYS set the "target" parameter to the actual target domain/IP from this mission.

YOUR ROLE:
- Run security tools to scan the target
- Analyze tool output to identify vulnerabilities
- Chain tools together (e.g. nmap → nuclei → report)
- Record findings using record_vulnerability tool
- Provide clear analysis and recommendations

WORKFLOW:
1. Start with reconnaissance (nmap, httpx, subfinder)
2. Based on findings, run deeper scans (nuclei, gobuster, testssl)
3. Analyze results and identify vulnerabilities
4. Record each vulnerability found
5. Provide a summary with risk assessment

RULES:
- Always explain what you're doing and why
- After each tool completes, analyze the output before running the next tool
- Record any vulnerability found using the record_vulnerability tool
- Be thorough but efficient — don't run unnecessary scans
- Provide remediation advice for each finding

TOOL USAGE TIPS:
- nmap: Use "-sV -T4 --top-ports 1000" for quick scan. NEVER use -p- (too slow). Use "-p 22,80,443,8080" for specific ports.
- nuclei: Always include "-severity critical,high,medium -timeout 30". Scans can be slow.
- httpx: Use "-silent -status-code -title -tech-detect -nc" for clean output.
- subfinder: Use "-silent -timeout 30" for quick subdomain enum.
- gobuster: Needs "-w /usr/share/wordlists/dirb/common.txt". Use "dir" mode.
- sqlmap: Always use "--batch --level=1 --risk=1" for non-interactive mode.
- nikto: Use "-ask no -maxtime 60s" to prevent hanging.
- testssl: Use "--quiet" flag. Target format: "host:port".
- hydra: Complex tool — only use when credentials testing is needed.

IMPORTANT: Keep scans fast. Use --top-ports, -T4, timeouts. Never run full port scans.`,
		missionName, missionDesc, targetStr,
	)

	// 5. Get provider from the swarm's router and build tool definitions
	providerRouter := h.swarm.GetRouter()
	if providerRouter == nil {
		slog.Error("provider router not available for AI processing")
		return
	}

	// Built-in tool: record_vulnerability — AI calls this to save findings to DB
	recordVulnTool := provider.Tool{
		Name:        "record_vulnerability",
		Description: "Record a discovered vulnerability to the database. Call this for EVERY vulnerability you find.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"title":       map[string]any{"type": "string", "description": "Vulnerability title"},
				"description": map[string]any{"type": "string", "description": "Detailed description"},
				"severity":    map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}, "description": "Severity level"},
				"target":      map[string]any{"type": "string", "description": "Affected host/URL"},
				"evidence":    map[string]any{"type": "string", "description": "Evidence from tool output"},
				"remediation": map[string]any{"type": "string", "description": "Recommended fix"},
			},
			"required": []string{"title", "severity", "target"},
		},
	}

	// Build available tools list — limit to core tools to avoid overloading local LLMs.
	coreTools := map[string]bool{
		"nmap": true, "nuclei": true, "httpx": true, "amass": true,
		"gobuster": true, "testssl": true, "hydra": true, "subfinder": true,
		"naabu": true, "feroxbuster": true, "nikto": true, "sqlmap": true,
		"ffuf": true, "dirsearch": true, "wpscan": true,
	}
	tools := []provider.Tool{recordVulnTool}
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

	// 6. ReAct Loop — AI reasons, calls tools, analyzes results, decides next step
	const maxIterations = 10
	executor := h.swarm.GetExecutor()

	for iteration := 0; iteration < maxIterations; iteration++ {
		slog.Info("AI iteration", "conversation_id", convID, "iteration", iteration+1)

		resp, err := providerRouter.ChatCompletion(ctx, provider.ChatRequest{
			System:    systemPrompt,
			Messages:  messages,
			Tools:     tools,
			MaxTokens: 4096,
		})
		if err != nil {
			slog.Error("AI chat completion failed", "conversation_id", convID, "iteration", iteration+1, "error", err)
			h.saveAndBroadcast(ctx, convID, missionID, fmt.Sprintf("[AI Error: %v]", err), nil)
			return
		}

		// No tool calls = AI is done, save final response
		if len(resp.ToolCalls) == 0 {
			if resp.Content != "" {
				h.saveAndBroadcast(ctx, convID, missionID, resp.Content, &resp.Model)
			}
			slog.Info("AI processing complete — no more tool calls",
				"conversation_id", convID, "iterations", iteration+1)
			return
		}

		// Execute each tool call
		if executor == nil {
			h.saveAndBroadcast(ctx, convID, missionID, "[Error: Tool executor not available]", nil)
			return
		}

		// Save assistant message with tool_calls
		toolCallsJSON, _ := json.Marshal(resp.ToolCalls)
		h.db.Pool.Exec(ctx,
			`INSERT INTO messages (conversation_id, role, content, tool_calls, model)
			 VALUES ($1, 'assistant', $2, $3, $4)`,
			convID, resp.Content, toolCallsJSON, resp.Model)

		for _, tc := range resp.ToolCalls {
			slog.Info("executing tool", "tool", tc.Name, "params", tc.Input, "conversation_id", convID)

			// Handle built-in record_vulnerability tool
			if tc.Name == "record_vulnerability" {
				vulnID := uuid.New()
				title, _ := tc.Input["title"].(string)
				desc, _ := tc.Input["description"].(string)
				severity, _ := tc.Input["severity"].(string)
				target, _ := tc.Input["target"].(string)
				evidence, _ := tc.Input["evidence"].(string)
				remediation, _ := tc.Input["remediation"].(string)

				_, err := h.db.Pool.Exec(ctx,
					`INSERT INTO vulnerabilities (id, mission_id, conversation_id, title, description, severity, target, evidence, remediation, found_by, status)
					 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ai-agent', 'open')`,
					vulnID, missionID, convID, title, desc, severity, target, evidence, remediation)
				toolOutput := fmt.Sprintf("Vulnerability recorded: %s [%s] on %s (ID: %s)", title, severity, target, vulnID)
				if err != nil {
					toolOutput = fmt.Sprintf("Failed to record vulnerability: %v", err)
				} else {
					slog.Info("vulnerability recorded by AI", "id", vulnID, "title", title, "severity", severity)
					if h.hub != nil {
						h.hub.Broadcast(missionID, WSEvent{Type: "vuln_found", Data: map[string]any{
							"id": vulnID, "title": title, "severity": severity, "target": target,
						}})
					}
				}
				messages = append(messages, provider.Message{Role: "assistant", Content: resp.Content, ToolCalls: resp.ToolCalls})
				messages = append(messages, provider.Message{Role: "tool", Content: toolOutput, ToolCallID: tc.ID, Name: tc.Name})
				h.db.Pool.Exec(ctx, `INSERT INTO messages (conversation_id, role, content, tool_call_id) VALUES ($1, 'tool', $2, $3)`,
					convID, toolOutput, tc.ID)
				continue
			}

			// Broadcast tool_start
			if h.hub != nil {
				h.hub.Broadcast(missionID, WSEvent{Type: "tool_start", Data: map[string]any{
					"tool": tc.Name, "params": tc.Input,
				}})
			}

			result, execErr := executor.Execute(ctx, tc.Name, tc.Input, &missionID, &convID)

			var toolOutput string
			if execErr != nil {
				toolOutput = fmt.Sprintf("Error: %v", execErr)
				if h.hub != nil {
					h.hub.Broadcast(missionID, WSEvent{Type: "tool_error", Data: map[string]any{
						"tool": tc.Name, "error": execErr.Error(),
					}})
				}
			} else {
				toolOutput = result.Stdout
				if result.Stderr != "" {
					toolOutput += "\n[STDERR]: " + result.Stderr
				}
				// Truncate long output
				if len(toolOutput) > 10000 {
					toolOutput = toolOutput[:10000] + "\n... [truncated]"
				}
				if h.hub != nil {
					h.hub.Broadcast(missionID, WSEvent{Type: "tool_complete", Data: map[string]any{
						"tool": tc.Name, "exit_code": result.ExitCode,
						"duration_ms": result.Duration.Milliseconds(),
					}})
				}
				slog.Info("tool completed", "tool", tc.Name, "exit_code", result.ExitCode,
					"duration_ms", result.Duration.Milliseconds(), "output_len", len(toolOutput))
			}

			// Add tool result to message history for AI to analyze
			messages = append(messages, provider.Message{
				Role:       "assistant",
				Content:    resp.Content,
				ToolCalls:  resp.ToolCalls,
			})
			messages = append(messages, provider.Message{
				Role:       "tool",
				Content:    toolOutput,
				ToolCallID: tc.ID,
				Name:       tc.Name,
			})

			// Save tool result as message in DB
			h.db.Pool.Exec(ctx,
				`INSERT INTO messages (conversation_id, role, content, tool_call_id)
				 VALUES ($1, 'tool', $2, $3)`,
				convID, toolOutput, tc.ID)
		}

		// Continue loop — AI will see tool results and decide next step
	}

	slog.Warn("AI hit max iterations", "conversation_id", convID, "max", maxIterations)
	h.saveAndBroadcast(ctx, convID, missionID, "[Maximum iterations reached. Analysis may be incomplete.]", nil)
}

// saveAndBroadcast saves an assistant message and broadcasts it via WebSocket.
func (h *Handler) saveAndBroadcast(ctx context.Context, convID, missionID uuid.UUID, content string, model *string) {
	var msgID uuid.UUID
	err := h.db.Pool.QueryRow(ctx,
		`INSERT INTO messages (conversation_id, role, content, model)
		 VALUES ($1, 'assistant', $2, $3) RETURNING id`,
		convID, content, model,
	).Scan(&msgID)
	if err != nil {
		slog.Error("failed to save assistant message", "error", err)
		return
	}

	if h.hub != nil {
		h.hub.Broadcast(missionID, WSEvent{
			Type: "message",
			Data: map[string]any{
				"id": msgID, "conversation_id": convID,
				"role": "assistant", "content": content, "model": model,
			},
		})
	}
}
