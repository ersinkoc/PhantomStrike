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

// OllamaProvider implements the Provider interface for Ollama local models.
type OllamaProvider struct {
	baseURL string
	model   string
	client  *http.Client
}

// NewOllamaProvider creates a new Ollama provider.
func NewOllamaProvider(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		client:  &http.Client{},
	}
}

func (o *OllamaProvider) Name() string              { return "ollama" }
func (o *OllamaProvider) SupportsToolCalling() bool  { return true }
func (o *OllamaProvider) MaxContextWindow(_ string) int { return 128000 }

func (o *OllamaProvider) Models(ctx context.Context) ([]Model, error) {
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", o.baseURL+"/api/tags", nil)
	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("listing models: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &result)

	var models []Model
	for _, m := range result.Models {
		models = append(models, Model{ID: m.Name, Name: m.Name, ContextWindow: 128000})
	}
	return models, nil
}

func (o *OllamaProvider) Embedding(ctx context.Context, input []string) ([][]float64, error) {
	var embeddings [][]float64
	for _, text := range input {
		body, _ := json.Marshal(map[string]any{
			"model":  o.model,
			"prompt": text,
		})
		httpReq, _ := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/api/embeddings", bytes.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := o.client.Do(httpReq)
		if err != nil {
			return nil, err
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result struct {
			Embedding []float64 `json:"embedding"`
		}
		_ = json.Unmarshal(respBody, &result)
		embeddings = append(embeddings, result.Embedding)
	}
	return embeddings, nil
}

// ChatCompletion sends a request to Ollama's chat API.
func (o *OllamaProvider) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = o.model
	}

	var msgs []map[string]any
	if req.System != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]any{"role": m.Role, "content": m.Content})
	}

	body := map[string]any{
		"model":    model,
		"messages": msgs,
		"stream":   false,
	}

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

	jsonBody, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/api/chat", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Message struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		PromptEvalCount int `json:"prompt_eval_count"`
		EvalCount       int `json:"eval_count"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	chatResp := &ChatResponse{
		Model:   model,
		Content: apiResp.Message.Content,
		Usage: Usage{
			InputTokens:  apiResp.PromptEvalCount,
			OutputTokens: apiResp.EvalCount,
		},
	}

	for _, tc := range apiResp.Message.ToolCalls {
		chatResp.ToolCalls = append(chatResp.ToolCalls, ToolCall{
			ID:    fmt.Sprintf("tc_%s", tc.Function.Name),
			Name:  tc.Function.Name,
			Input: tc.Function.Arguments,
		})
	}

	return chatResp, nil
}

func (o *OllamaProvider) StreamChatCompletion(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
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
		ch <- StreamEvent{Type: "done", Usage: &resp.Usage}
	}()
	return ch, nil
}
