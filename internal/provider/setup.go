package provider

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

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

// SetupRouterFromDB creates a provider router configured from database entries.
// It loads enabled+configured providers from ai_providers, creates the appropriate
// Provider instances, queries ai_preferences for agent overrides, and builds the
// fallback chain based on priority ordering. Environment variables and the static
// config are used as fallbacks for providers not yet in the database.
func SetupRouterFromDB(ctx context.Context, pool *pgxpool.Pool, cfgProviders config.ProvidersConfig) *Router {
	// Start with config-based defaults for the fallback chain and default name.
	router := NewRouter(cfgProviders.Default, cfgProviders.FallbackChain)

	// 1. Query enabled + configured providers from the database, ordered by priority.
	rows, err := pool.Query(ctx,
		`SELECT id, api_key, api_base_url, sdk_type, is_local
		 FROM ai_providers
		 WHERE is_enabled = true AND is_configured = true
		 ORDER BY priority ASC`)
	if err != nil {
		slog.Warn("failed to query DB providers, falling back to config", "error", err)
		return SetupRouter(cfgProviders)
	}
	defer rows.Close()

	var dbFallback []string

	for rows.Next() {
		var (
			id, apiKey, apiBaseURL, sdkType string
			isLocal                         bool
		)
		if err := rows.Scan(&id, &apiKey, &apiBaseURL, &sdkType, &isLocal); err != nil {
			slog.Warn("failed to scan DB provider row", "error", err)
			continue
		}

		// If no API key in DB, try the corresponding env var
		if apiKey == "" && !isLocal {
			envKey := strings.ToUpper(id) + "_API_KEY"
			apiKey = os.Getenv(envKey)
			if apiKey == "" {
				slog.Debug("skipping DB provider, no API key", "id", id)
				continue
			}
		}

		// Pick a default model for this provider from the DB
		var defaultModel string
		_ = pool.QueryRow(ctx,
			`SELECT id FROM ai_models WHERE provider_id = $1 AND is_enabled = true
			 ORDER BY context_window DESC LIMIT 1`, id,
		).Scan(&defaultModel)

		// Create the appropriate provider instance
		var p Provider
		switch sdkType {
		case "anthropic":
			p = NewAnthropicProvider(apiKey, defaultModel, 8192)
		case "openai":
			p = NewOpenAIProvider(apiKey, apiBaseURL, defaultModel, 4096)
		case "openai_compatible":
			if apiBaseURL == "" {
				if preset, ok := OpenAICompatiblePresets[id]; ok {
					apiBaseURL = preset.DefaultBaseURL
				}
			}
			p = NewOpenAIProvider(apiKey, apiBaseURL, defaultModel, 4096)
		case "ollama":
			if apiBaseURL == "" {
				apiBaseURL = "http://localhost:11434"
			}
			p = NewOllamaProvider(apiBaseURL, defaultModel)
		default:
			// Treat unknown SDK types as OpenAI-compatible
			p = NewOpenAIProvider(apiKey, apiBaseURL, defaultModel, 4096)
		}

		router.Register(id, p)
		dbFallback = append(dbFallback, id)
		slog.Info("registered DB provider", "id", id, "sdk_type", sdkType, "model", defaultModel)
	}

	// 2. Also register providers from config/env that aren't in DB yet (existing behavior).
	if _, ok := router.Get("anthropic"); !ok && cfgProviders.Anthropic.APIKey != "" {
		p := NewAnthropicProvider(cfgProviders.Anthropic.APIKey, cfgProviders.Anthropic.Model, cfgProviders.Anthropic.MaxTokens)
		router.Register("anthropic", p)
		slog.Info("registered config provider", "name", "anthropic")
	}
	if _, ok := router.Get("openai"); !ok && cfgProviders.OpenAI.APIKey != "" {
		p := NewOpenAIProvider(cfgProviders.OpenAI.APIKey, cfgProviders.OpenAI.BaseURL, cfgProviders.OpenAI.Model, cfgProviders.OpenAI.MaxTokens)
		router.Register("openai", p)
		slog.Info("registered config provider", "name", "openai")
	}
	if _, ok := router.Get("ollama"); !ok && cfgProviders.Ollama.BaseURL != "" {
		p := NewOllamaProvider(cfgProviders.Ollama.BaseURL, cfgProviders.Ollama.Model)
		router.Register("ollama", p)
		slog.Info("registered config provider", "name", "ollama")
	}
	if _, ok := router.Get("groq"); !ok && cfgProviders.Groq.APIKey != "" {
		p := NewGroqProvider(cfgProviders.Groq.APIKey, cfgProviders.Groq.Model)
		router.Register("groq", p)
		slog.Info("registered config provider", "name", "groq")
	}
	if _, ok := router.Get("azure"); !ok && cfgProviders.Azure.APIKey != "" && cfgProviders.Azure.BaseURL != "" {
		p := NewOpenAIProvider(cfgProviders.Azure.APIKey, cfgProviders.Azure.BaseURL, cfgProviders.Azure.Model, cfgProviders.Azure.MaxTokens)
		router.Register("azure", p)
		slog.Info("registered config provider", "name", "azure")
	}

	// 3. Use DB-derived fallback chain if we loaded providers from DB.
	if len(dbFallback) > 0 {
		router.SetFallbackChain(dbFallback)
	}

	// 4. Query ai_preferences for agent overrides.
	prefRows, err := pool.Query(ctx,
		`SELECT key, provider_id FROM ai_preferences`)
	if err == nil {
		defer prefRows.Close()
		for prefRows.Next() {
			var key, providerID string
			if err := prefRows.Scan(&key, &providerID); err != nil {
				continue
			}
			// Map preference keys to agent overrides
			// "default" preference updates the router's default
			if key == "default" {
				if p, ok := router.Get(providerID); ok {
					router.Register("default", p)
				}
			} else {
				// planner, executor, reviewer, etc.
				if p, ok := router.Get(providerID); ok {
					router.Register(key, p)
					slog.Debug("DB agent preference override", "role", key, "provider", providerID)
				}
			}
		}
	}

	// 5. Also apply config-based agent overrides as a fallback.
	for agentType, providerName := range cfgProviders.AgentOverrides {
		// Only apply if not already set from DB preferences
		if _, ok := router.Get(agentType); !ok {
			if p, ok := router.Get(providerName); ok {
				router.Register(agentType, p)
				slog.Debug("config agent override", "agent", agentType, "provider", providerName)
			}
		}
	}

	return router
}

// AutoSyncModels checks if models have been synced and triggers a sync if not.
// This should be called after DB connection and migration on first startup.
func AutoSyncModels(ctx context.Context, pool *pgxpool.Pool) {
	var synced string
	err := pool.QueryRow(ctx,
		`SELECT value::text FROM setup_state WHERE key = 'models_last_synced'`,
	).Scan(&synced)

	// If the row doesn't exist, the query errors, or the value is "null", sync is needed.
	needsSync := err != nil || synced == "" || synced == "null" || synced == `"null"`

	if !needsSync {
		slog.Info("models already synced, skipping auto-sync", "last_synced", synced)
		return
	}

	slog.Info("first startup detected, syncing models from models.dev...")
	providerCount, modelCount, err := SyncFromModelsDev(ctx, pool)
	if err != nil {
		slog.Warn("auto-sync from models.dev failed", "error", err)
		return
	}
	slog.Info("auto-sync completed",
		"providers", providerCount,
		"models", modelCount,
	)
}
