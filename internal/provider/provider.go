package provider

import "context"

// Provider is the interface for LLM providers.
type Provider interface {
	// ChatCompletion sends a chat request and returns the full response.
	ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error)

	// StreamChatCompletion sends a chat request and streams response events.
	StreamChatCompletion(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error)

	// Embedding generates vector embeddings for the given texts.
	Embedding(ctx context.Context, input []string) ([][]float64, error)

	// Models returns the list of available models.
	Models(ctx context.Context) ([]Model, error)

	// Name returns the provider identifier.
	Name() string

	// SupportsToolCalling indicates if this provider supports tool/function calling.
	SupportsToolCalling() bool

	// MaxContextWindow returns the max token count for the given model.
	MaxContextWindow(model string) int
}

// ChatRequest represents a chat completion request.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []Tool    `json:"tools,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	TopP        float64   `json:"top_p,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
	System      string    `json:"system,omitempty"`
}

// ChatResponse represents a chat completion response.
type ChatResponse struct {
	ID        string    `json:"id"`
	Model     string    `json:"model"`
	Content   string    `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	Usage     Usage     `json:"usage"`
	StopReason string   `json:"stop_reason"`
}

// Message represents a conversation message.
type Message struct {
	Role       string    `json:"role"`
	Content    string    `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string    `json:"tool_call_id,omitempty"`
	Name       string    `json:"name,omitempty"`
}

// Tool represents a tool definition for function calling.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// ToolCall represents a tool call from the LLM.
type ToolCall struct {
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

// StreamEvent represents a streaming response event.
type StreamEvent struct {
	Type      string    `json:"type"` // text_delta, tool_call, done, error
	Delta     string    `json:"delta,omitempty"`
	ToolCall  *ToolCall `json:"tool_call,omitempty"`
	Usage     *Usage    `json:"usage,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Usage represents token usage information.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Model represents a model available from a provider.
type Model struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ContextWindow int    `json:"context_window"`
}
