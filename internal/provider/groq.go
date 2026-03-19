package provider

// GroqProvider uses the OpenAI-compatible API with Groq's endpoint.
// Since Groq is OpenAI-compatible, we wrap OpenAIProvider with Groq defaults.

// NewGroqProvider creates a Groq provider (OpenAI-compatible).
func NewGroqProvider(apiKey, model string) *OpenAIProvider {
	if model == "" {
		model = "llama-3.3-70b-versatile"
	}
	p := NewOpenAIProvider(apiKey, "https://api.groq.com/openai/v1", model, 4096)
	return p
}
