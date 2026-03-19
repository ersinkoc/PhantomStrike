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

// OpenAIProvider implements the Provider interface for OpenAI Chat Completions API.
type OpenAIProvider struct {
	apiKey    string
	baseURL   string
	model     string
	maxTokens int
	client    *http.Client
}

// NewOpenAIProvider creates a new OpenAI provider.
func NewOpenAIProvider(apiKey, baseURL, model string, maxTokens int) *OpenAIProvider {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	return &OpenAIProvider{
		apiKey:    apiKey,
		baseURL:   strings.TrimRight(baseURL, "/"),
		model:     model,
		maxTokens: maxTokens,
		client:    &http.Client{},
	}
}

func (o *OpenAIProvider) Name() string              { return "openai" }
func (o *OpenAIProvider) SupportsToolCalling() bool  { return true }
func (o *OpenAIProvider) MaxContextWindow(model string) int {
	switch {
	case strings.Contains(model, "gpt-4o"):
		return 128000
	case strings.Contains(model, "gpt-4-turbo"):
		return 128000
	case strings.Contains(model, "gpt-4"):
		return 8192
	case strings.Contains(model, "gpt-3.5"):
		return 16385
	default:
		return 128000
	}
}

func (o *OpenAIProvider) Models(ctx context.Context) ([]Model, error) {
	return []Model{
		{ID: "gpt-4o", Name: "GPT-4o", ContextWindow: 128000},
		{ID: "gpt-4o-mini", Name: "GPT-4o Mini", ContextWindow: 128000},
		{ID: "gpt-4-turbo", Name: "GPT-4 Turbo", ContextWindow: 128000},
	}, nil
}

func (o *OpenAIProvider) Embedding(ctx context.Context, input []string) ([][]float64, error) {
	body := map[string]any{
		"model": "text-embedding-3-large",
		"input": input,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/embeddings", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("embedding API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	embeddings := make([][]float64, len(result.Data))
	for i, d := range result.Data {
		embeddings[i] = d.Embedding
	}
	return embeddings, nil
}

// ChatCompletion sends a request to OpenAI Chat Completions API.
func (o *OpenAIProvider) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = o.model
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = o.maxTokens
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
	}

	// Build messages
	var msgs []map[string]any

	// System message
	if req.System != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": req.System})
	}

	for _, m := range req.Messages {
		msg := map[string]any{"role": m.Role, "content": m.Content}

		if len(m.ToolCalls) > 0 {
			var toolCalls []map[string]any
			for _, tc := range m.ToolCalls {
				inputJSON, _ := json.Marshal(tc.Input)
				toolCalls = append(toolCalls, map[string]any{
					"id":   tc.ID,
					"type": "function",
					"function": map[string]any{
						"name":      tc.Name,
						"arguments": string(inputJSON),
					},
				})
			}
			msg["tool_calls"] = toolCalls
		}

		if m.ToolCallID != "" {
			msg["tool_call_id"] = m.ToolCallID
		}

		msgs = append(msgs, msg)
	}
	body["messages"] = msgs

	// Tools
	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			tools = append(tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  t.InputSchema,
				},
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("openai API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp openaiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return apiResp.toChatResponse(), nil
}

// StreamChatCompletion sends a streaming request.
func (o *OpenAIProvider) StreamChatCompletion(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	ch := make(chan StreamEvent, 100)
	go func() {
		defer close(ch)
		resp, err := o.ChatCompletion(ctx, req)
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

// --- OpenAI API types ---

type openaiResponse struct {
	ID      string         `json:"id"`
	Model   string         `json:"model"`
	Choices []openaiChoice `json:"choices"`
	Usage   openaiUsage    `json:"usage"`
}

type openaiChoice struct {
	Message      openaiMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openaiMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []openaiToolCall `json:"tool_calls,omitempty"`
}

type openaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

func (r *openaiResponse) toChatResponse() *ChatResponse {
	resp := &ChatResponse{
		ID:    r.ID,
		Model: r.Model,
		Usage: Usage{
			InputTokens:  r.Usage.PromptTokens,
			OutputTokens: r.Usage.CompletionTokens,
		},
	}

	if len(r.Choices) > 0 {
		choice := r.Choices[0]
		resp.Content = choice.Message.Content
		resp.StopReason = choice.FinishReason

		for _, tc := range choice.Message.ToolCalls {
			var input map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &input)
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: input,
			})
		}
	}

	return resp
}
