package api

import "net/http"

func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	// Return non-sensitive configuration
	writeJSON(w, http.StatusOK, map[string]any{
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
	})
}

func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	// Settings updates would modify the runtime config
	// For now, return a stub
	writeJSON(w, http.StatusOK, map[string]string{"status": "settings update not yet implemented"})
}
