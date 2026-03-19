package provider

import (
	"log/slog"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

// SetupRouter initializes all configured providers and returns a ready Router.
func SetupRouter(cfg config.ProvidersConfig) *Router {
	router := NewRouter(cfg.Default, cfg.FallbackChain)

	// Anthropic
	if cfg.Anthropic.APIKey != "" {
		p := NewAnthropicProvider(cfg.Anthropic.APIKey, cfg.Anthropic.Model, cfg.Anthropic.MaxTokens)
		router.Register("anthropic", p)
		slog.Info("registered provider", "name", "anthropic", "model", cfg.Anthropic.Model)
	}

	// OpenAI
	if cfg.OpenAI.APIKey != "" {
		p := NewOpenAIProvider(cfg.OpenAI.APIKey, cfg.OpenAI.BaseURL, cfg.OpenAI.Model, cfg.OpenAI.MaxTokens)
		router.Register("openai", p)
		slog.Info("registered provider", "name", "openai", "model", cfg.OpenAI.Model)
	}

	// Ollama (no API key required)
	if cfg.Ollama.BaseURL != "" {
		p := NewOllamaProvider(cfg.Ollama.BaseURL, cfg.Ollama.Model)
		router.Register("ollama", p)
		slog.Info("registered provider", "name", "ollama", "model", cfg.Ollama.Model)
	}

	// Groq
	if cfg.Groq.APIKey != "" {
		p := NewGroqProvider(cfg.Groq.APIKey, cfg.Groq.Model)
		router.Register("groq", p)
		slog.Info("registered provider", "name", "groq", "model", cfg.Groq.Model)
	}

	// Register agent overrides
	for agentType, providerName := range cfg.AgentOverrides {
		if p, ok := router.Get(providerName); ok {
			router.Register(agentType, p)
			slog.Debug("agent provider override", "agent", agentType, "provider", providerName)
		}
	}

	return router
}
