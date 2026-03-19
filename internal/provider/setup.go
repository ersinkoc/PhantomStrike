package provider

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

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

	// Azure OpenAI
	if cfg.Azure.APIKey != "" && cfg.Azure.BaseURL != "" {
		p := NewOpenAIProvider(cfg.Azure.APIKey, cfg.Azure.BaseURL, cfg.Azure.Model, cfg.Azure.MaxTokens)
		router.Register("azure", p)
		slog.Info("registered provider", "name", "azure", "model", cfg.Azure.Model)
	}

	// Register additional OpenAI-compatible providers from config
	for name, pc := range cfg.Additional {
		if pc.APIKey == "" {
			slog.Warn("skipping additional provider, no API key", "name", name)
			continue
		}
		baseURL := pc.BaseURL
		if baseURL == "" {
			// Try to get from preset
			if preset, ok := OpenAICompatiblePresets[name]; ok {
				baseURL = preset.DefaultBaseURL
			}
		}
		if baseURL == "" {
			slog.Warn("skipping additional provider, no base URL", "name", name)
			continue
		}

		p := NewOpenAIProvider(pc.APIKey, baseURL, pc.Model, pc.MaxTokens)
		router.Register(name, p)
		slog.Info("registered provider", "name", name, "model", pc.Model, "base_url", baseURL)
	}

	// Register providers from environment variables for popular presets
	registerEnvProviders(router)

	// Register agent overrides
	for agentType, providerName := range cfg.AgentOverrides {
		if p, ok := router.Get(providerName); ok {
			router.Register(agentType, p)
			slog.Debug("agent provider override", "agent", agentType, "provider", providerName)
		}
	}

	return router
}

// registerEnvProviders registers providers from environment variables.
// This allows users to add providers without modifying config files.
func registerEnvProviders(router *Router) {
	// Check for PROVIDERS env var (comma-separated list of provider names)
	if providersEnv := os.Getenv("PROVIDERS"); providersEnv != "" {
		names := strings.Split(providersEnv, ",")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}

			// Check if already registered from config
			if _, ok := router.Get(name); ok {
				continue
			}

			// Try to register from preset
			if preset, ok := OpenAICompatiblePresets[name]; ok {
				apiKeyEnv := strings.ToUpper(name) + "_API_KEY"
				apiKey := os.Getenv(apiKeyEnv)
				if apiKey == "" && name == "openrouter" {
					apiKey = os.Getenv("OPENROUTER_API_KEY")
				}
				if apiKey == "" && name == "ai21" {
					apiKey = os.Getenv("AI21_API_KEY")
				}

				if apiKey == "" {
					slog.Debug("provider preset found but no API key", "name", name, "env_var", apiKeyEnv)
					continue
				}

				modelEnv := strings.ToUpper(name) + "_MODEL"
				model := os.Getenv(modelEnv)
				if model == "" {
					// Use default models based on provider
					switch name {
					case "deepseek":
						model = "deepseek-chat"
					case "glm":
						model = "glm-4"
					case "together":
						model = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
					case "mistral":
						model = "mistral-large-latest"
					case "cohere":
						model = "command-r-plus"
					case "fireworks":
						model = "accounts/fireworks/models/llama-v3p1-70b-instruct"
					case "perplexity":
						model = "llama-3.1-sonar-large-128k-online"
					case "gemini":
						model = "gemini-1.5-pro"
					case "openrouter":
						model = "anthropic/claude-3.5-sonnet"
					case "ai21":
						model = "jamba-1.5-large"
					default:
						model = "default"
					}
				}

				p := NewOpenAIProvider(apiKey, preset.DefaultBaseURL, model, 4096)
				router.Register(name, p)
				slog.Info("registered provider from env", "name", name, "model", model)
			}
		}
	}
}

// RegisterProviderFromConfig manually registers a provider at runtime.
// This can be used by the API to dynamically add providers.
func (r *Router) RegisterProviderFromConfig(name string, pc config.ProviderConfig, providerType string) error {
	if pc.APIKey == "" {
		return fmt.Errorf("API key required for provider %s", name)
	}

	switch providerType {
	case "anthropic":
		p := NewAnthropicProvider(pc.APIKey, pc.Model, pc.MaxTokens)
		r.Register(name, p)
	case "openai", "openai_compatible":
		baseURL := pc.BaseURL
		if baseURL == "" {
			if preset, ok := OpenAICompatiblePresets[name]; ok {
				baseURL = preset.DefaultBaseURL
			}
		}
		if baseURL == "" {
			return fmt.Errorf("base URL required for OpenAI-compatible provider %s", name)
		}
		p := NewOpenAIProvider(pc.APIKey, baseURL, pc.Model, pc.MaxTokens)
		r.Register(name, p)
	case "ollama":
		if pc.BaseURL == "" {
			return fmt.Errorf("base URL required for Ollama provider %s", name)
		}
		p := NewOllamaProvider(pc.BaseURL, pc.Model)
		r.Register(name, p)
	default:
		return fmt.Errorf("unknown provider type: %s", providerType)
	}

	slog.Info("registered provider dynamically", "name", name, "type", providerType)
	return nil
}
