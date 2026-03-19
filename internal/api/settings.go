package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/auth"
)

func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	// Check cache first
	if h.cache != nil {
		var cached map[string]any
		if err := h.cache.GetJSON(r.Context(), "api:settings", &cached); err == nil {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

	result := map[string]any{
		"providers": map[string]any{
			"default":        h.cfg.Providers.Default,
			"fallback_chain": h.cfg.Providers.FallbackChain,
			"anthropic":      map[string]any{"model": h.cfg.Providers.Anthropic.Model, "configured": h.cfg.Providers.Anthropic.APIKey != ""},
			"openai":         map[string]any{"model": h.cfg.Providers.OpenAI.Model, "configured": h.cfg.Providers.OpenAI.APIKey != ""},
			"ollama":         map[string]any{"model": h.cfg.Providers.Ollama.Model, "base_url": h.cfg.Providers.Ollama.BaseURL},
			"groq":           map[string]any{"model": h.cfg.Providers.Groq.Model, "configured": h.cfg.Providers.Groq.APIKey != ""},
		},
		"agent": map[string]any{
			"max_iterations":     h.cfg.Agent.MaxIterations,
			"max_parallel_tools": h.cfg.Agent.MaxParallelTools,
			"auto_review":        h.cfg.Agent.AutoReview,
		},
		"mcp": map[string]any{
			"enabled": h.cfg.MCP.Server.Enabled,
			"port":    h.cfg.MCP.Server.Port,
		},
		"auth": map[string]any{
			"allow_registration": h.cfg.Auth.AllowRegistration,
		},
	}

	// Cache the result
	if h.cache != nil {
		_ = h.cache.SetJSON(r.Context(), "api:settings", result, 10*time.Minute)
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req map[string]json.RawMessage
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req) == 0 {
		writeError(w, http.StatusBadRequest, "no settings provided")
		return
	}

	// Process each settings section and persist to DB + update in-memory config
	for key, raw := range req {
		// Store in settings table (key-value JSONB)
		_, err := h.db.Pool.Exec(r.Context(),
			`INSERT INTO settings (key, value, updated_by, updated_at)
			 VALUES ($1, $2, $3, NOW())
			 ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = NOW()`,
			key, raw, claims.UserID,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist setting: "+key)
			return
		}

		// Update in-memory config for immediate effect
		switch key {
		case "providers":
			var providers struct {
				Default       string   `json:"default"`
				FallbackChain []string `json:"fallback_chain"`
				Anthropic     struct {
					Model string `json:"model"`
				} `json:"anthropic"`
				OpenAI struct {
					Model string `json:"model"`
				} `json:"openai"`
				Ollama struct {
					Model   string `json:"model"`
					BaseURL string `json:"base_url"`
				} `json:"ollama"`
				Groq struct {
					Model string `json:"model"`
				} `json:"groq"`
			}
			if err := json.Unmarshal(raw, &providers); err == nil {
				if providers.Default != "" {
					h.cfg.Providers.Default = providers.Default
				}
				if len(providers.FallbackChain) > 0 {
					h.cfg.Providers.FallbackChain = providers.FallbackChain
				}
				if providers.Anthropic.Model != "" {
					h.cfg.Providers.Anthropic.Model = providers.Anthropic.Model
				}
				if providers.OpenAI.Model != "" {
					h.cfg.Providers.OpenAI.Model = providers.OpenAI.Model
				}
				if providers.Ollama.Model != "" {
					h.cfg.Providers.Ollama.Model = providers.Ollama.Model
				}
				if providers.Ollama.BaseURL != "" {
					h.cfg.Providers.Ollama.BaseURL = providers.Ollama.BaseURL
				}
				if providers.Groq.Model != "" {
					h.cfg.Providers.Groq.Model = providers.Groq.Model
				}
			}

		case "agent":
			var agent struct {
				MaxIterations    *int  `json:"max_iterations"`
				MaxParallelTools *int  `json:"max_parallel_tools"`
				AutoReview       *bool `json:"auto_review"`
			}
			if err := json.Unmarshal(raw, &agent); err == nil {
				if agent.MaxIterations != nil {
					h.cfg.Agent.MaxIterations = *agent.MaxIterations
				}
				if agent.MaxParallelTools != nil {
					h.cfg.Agent.MaxParallelTools = *agent.MaxParallelTools
				}
				if agent.AutoReview != nil {
					h.cfg.Agent.AutoReview = *agent.AutoReview
				}
			}

		case "auth":
			var authSettings struct {
				AllowRegistration *bool `json:"allow_registration"`
			}
			if err := json.Unmarshal(raw, &authSettings); err == nil {
				if authSettings.AllowRegistration != nil {
					h.cfg.Auth.AllowRegistration = *authSettings.AllowRegistration
				}
			}

		case "mcp":
			var mcp struct {
				Enabled *bool `json:"enabled"`
				Port    *int  `json:"port"`
			}
			if err := json.Unmarshal(raw, &mcp); err == nil {
				if mcp.Enabled != nil {
					h.cfg.MCP.Server.Enabled = *mcp.Enabled
				}
				if mcp.Port != nil {
					h.cfg.MCP.Server.Port = *mcp.Port
				}
			}
		}
	}

	// Invalidate settings cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:settings")
	}

	// Return the updated count
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "updated",
		"updated": strconv.Itoa(len(req)) + " setting(s)",
	})
}
