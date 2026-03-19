package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const anthropicAPIURL = "https://api.anthropic.com/v1/messages"

// AnthropicProvider implements the Provider interface for Anthropic's Messages API.
type AnthropicProvider struct {
	apiKey    string
	model     string
	maxTokens int
	client    *http.Client
}

// NewAnthropicProvider creates a new Anthropic provider.
func NewAnthropicProvider(apiKey, model string, maxTokens int) *AnthropicProvider {
	if maxTokens <= 0 {
		maxTokens = 8192
	}
	return &AnthropicProvider{
		apiKey:    apiKey,
		model:     model,
		maxTokens: maxTokens,
		client:    &http.Client{},
	}
}

func (a *AnthropicProvider) Name() string              { return "anthropic" }
func (a *AnthropicProvider) SupportsToolCalling() bool  { return true }
func (a *AnthropicProvider) MaxContextWindow(model string) int {
	switch {
	case strings.Contains(model, "opus"):
		return 200000
	case strings.Contains(model, "sonnet"):
		return 200000
	case strings.Contains(model, "haiku"):
		return 200000
	default:
		return 200000
	}
}

func (a *AnthropicProvider) Models(ctx context.Context) ([]Model, error) {
	return []Model{
		{ID: "claude-sonnet-4-20250514", Name: "Claude Sonnet 4", ContextWindow: 200000},
		{ID: "claude-opus-4-20250514", Name: "Claude Opus 4", ContextWindow: 200000},
		{ID: "claude-haiku-4-20250514", Name: "Claude Haiku 4", ContextWindow: 200000},
	}, nil
}

func (a *AnthropicProvider) Embedding(ctx context.Context, input []string) ([][]float64, error) {
	return nil, fmt.Errorf("anthropic does not support native embeddings, use voyage API")
}

// ChatCompletion sends a request to Anthropic Messages API.
func (a *AnthropicProvider) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = a.model
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = a.maxTokens
	}

	// Build Anthropic request body
	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
	}

	// System message
	if req.System != "" {
		body["system"] = req.System
	}

	// Convert messages
	var msgs []map[string]any
	for _, m := range req.Messages {
		msg := map[string]any{"role": m.Role}

		if m.Role == "tool" {
			// Tool results use "user" role with tool_result content block
			msg["role"] = "user"
			msg["content"] = []map[string]any{{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			}}
		} else if len(m.ToolCalls) > 0 {
			// Assistant message with tool use
			var content []map[string]any
			if m.Content != "" {
				content = append(content, map[string]any{"type": "text", "text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				content = append(content, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": tc.Input,
				})
			}
			msg["content"] = content
		} else {
			msg["content"] = m.Content
		}

		msgs = append(msgs, msg)
	}
	body["messages"] = msgs

	// Tools
	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			tools = append(tools, map[string]any{
				"name":         t.Name,
				"description":  t.Description,
				"input_schema": t.InputSchema,
			})
		}
		body["tools"] = tools
	}

	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var apiResp anthropicResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return apiResp.toChatResponse(), nil
}

// StreamChatCompletion sends a streaming request to Anthropic Messages API.
func (a *AnthropicProvider) StreamChatCompletion(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	// For streaming, we set stream=true and parse SSE events
	// Simplified implementation - full SSE parsing in production
	ch := make(chan StreamEvent, 100)

	go func() {
		defer close(ch)

		// Use non-streaming for now and emit as single event
		resp, err := a.ChatCompletion(ctx, req)
		if err != nil {
			ch <- StreamEvent{Type: "error", Error: err.Error()}
			return
		}

		if resp.Content != "" {
			ch <- StreamEvent{Type: "text_delta", Delta: resp.Content}
		}
		for _, tc := range resp.ToolCalls {
			ch <- StreamEvent{Type: "tool_call", ToolCall: &tc}
		}
		ch <- StreamEvent{Type: "done", Usage: &resp.Usage}
	}()

	return ch, nil
}

// --- Anthropic API types ---

type anthropicResponse struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	Role       string              `json:"role"`
	Content    []anthropicContent  `json:"content"`
	Model      string              `json:"model"`
	StopReason string              `json:"stop_reason"`
	Usage      anthropicUsage      `json:"usage"`
}

type anthropicContent struct {
	Type  string         `json:"type"` // text, tool_use
	Text  string         `json:"text,omitempty"`
	ID    string         `json:"id,omitempty"`
	Name  string         `json:"name,omitempty"`
	Input map[string]any `json:"input,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func (r *anthropicResponse) toChatResponse() *ChatResponse {
	resp := &ChatResponse{
		ID:         r.ID,
		Model:      r.Model,
		StopReason: r.StopReason,
		Usage: Usage{
			InputTokens:  r.Usage.InputTokens,
			OutputTokens: r.Usage.OutputTokens,
		},
	}

	for _, c := range r.Content {
		switch c.Type {
		case "text":
			resp.Content += c.Text
		case "tool_use":
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:    c.ID,
				Name:  c.Name,
				Input: c.Input,
			})
		}
	}

	return resp
}
