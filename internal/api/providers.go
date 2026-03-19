package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/provider"
)

// --- Provider handlers ---

func (h *Handler) handleListProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT p.id, p.name, p.api_base_url, p.sdk_type, p.doc_url,
		        p.is_enabled, p.is_configured, p.is_local, p.priority,
		        p.env_var, p.synced_from, p.last_synced_at, p.settings,
		        COUNT(m.id) AS model_count
		 FROM ai_providers p
		 LEFT JOIN ai_models m ON m.provider_id = p.id
		 GROUP BY p.id
		 ORDER BY p.priority ASC, p.name ASC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query providers")
		return
	}
	defer rows.Close()

	var providers []map[string]any
	for rows.Next() {
		var (
			id, name, apiBaseURL, sdkType, docURL string
			isEnabled, isConfigured, isLocal       bool
			priority                               int
			envVar, syncedFrom                     string
			lastSyncedAt                           any
			settings                               json.RawMessage
			modelCount                             int
		)
		if err := rows.Scan(
			&id, &name, &apiBaseURL, &sdkType, &docURL,
			&isEnabled, &isConfigured, &isLocal, &priority,
			&envVar, &syncedFrom, &lastSyncedAt, &settings,
			&modelCount,
		); err != nil {
			continue
		}

		p := map[string]any{
			"id":             id,
			"name":           name,
			"api_base_url":   apiBaseURL,
			"sdk_type":       sdkType,
			"doc_url":        docURL,
			"is_enabled":     isEnabled,
			"is_configured":  isConfigured,
			"is_local":       isLocal,
			"priority":       priority,
			"env_var":        envVar,
			"synced_from":    syncedFrom,
			"last_synced_at": lastSyncedAt,
			"settings":       settings,
			"model_count":    modelCount,
		}
		// Never expose api_key in list responses
		providers = append(providers, p)
	}

	if providers == nil {
		providers = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

func (h *Handler) handleGetProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var (
		name, apiBaseURL, sdkType, docURL string
		isEnabled, isConfigured, isLocal  bool
		priority                          int
		envVar, syncedFrom                string
		lastSyncedAt                      any
		settings                          json.RawMessage
		apiKey                            string
	)

	err := h.db.Pool.QueryRow(r.Context(),
		`SELECT name, api_base_url, api_key, sdk_type, doc_url,
		        is_enabled, is_configured, is_local, priority,
		        env_var, synced_from, last_synced_at, settings
		 FROM ai_providers WHERE id = $1`, id,
	).Scan(&name, &apiBaseURL, &apiKey, &sdkType, &docURL,
		&isEnabled, &isConfigured, &isLocal, &priority,
		&envVar, &syncedFrom, &lastSyncedAt, &settings)
	if err != nil {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}

	// Mask API key: show only last 4 chars if configured
	maskedKey := ""
	if apiKey != "" && len(apiKey) > 4 {
		maskedKey = strings.Repeat("*", len(apiKey)-4) + apiKey[len(apiKey)-4:]
	} else if apiKey != "" {
		maskedKey = "****"
	}

	// Fetch associated models
	modelRows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, name, family, tool_call, reasoning, attachment,
		        context_window, max_output, cost_input, cost_output,
		        open_weights, is_enabled, knowledge_cutoff, release_date
		 FROM ai_models WHERE provider_id = $1
		 ORDER BY family, name`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query models")
		return
	}
	defer modelRows.Close()

	var models []map[string]any
	for modelRows.Next() {
		var (
			mID, mName, mFamily         string
			toolCall, reasoning, attach  bool
			ctxWindow, maxOut            int
			costIn, costOut              float64
			openWeights, mEnabled        bool
			knowledgeCutoff              string
			releaseDate                  any
		)
		if err := modelRows.Scan(
			&mID, &mName, &mFamily, &toolCall, &reasoning, &attach,
			&ctxWindow, &maxOut, &costIn, &costOut,
			&openWeights, &mEnabled, &knowledgeCutoff, &releaseDate,
		); err != nil {
			continue
		}
		models = append(models, map[string]any{
			"id":               mID,
			"name":             mName,
			"family":           mFamily,
			"tool_call":        toolCall,
			"reasoning":        reasoning,
			"attachment":       attach,
			"context_window":   ctxWindow,
			"max_output":       maxOut,
			"cost_input":       costIn,
			"cost_output":      costOut,
			"open_weights":     openWeights,
			"is_enabled":       mEnabled,
			"knowledge_cutoff": knowledgeCutoff,
			"release_date":     releaseDate,
		})
	}
	if models == nil {
		models = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":             id,
		"name":           name,
		"api_base_url":   apiBaseURL,
		"api_key":        maskedKey,
		"sdk_type":       sdkType,
		"doc_url":        docURL,
		"is_enabled":     isEnabled,
		"is_configured":  isConfigured,
		"is_local":       isLocal,
		"priority":       priority,
		"env_var":        envVar,
		"synced_from":    syncedFrom,
		"last_synced_at": lastSyncedAt,
		"settings":       settings,
		"models":         models,
	})
}

func (h *Handler) handleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		APIKey    *string          `json:"api_key"`
		IsEnabled *bool            `json:"is_enabled"`
		Priority  *int             `json:"priority"`
		Settings  *json.RawMessage `json:"settings"`
		BaseURL   *string          `json:"api_base_url"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Verify provider exists
	var exists bool
	err := h.db.Pool.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM ai_providers WHERE id = $1)`, id,
	).Scan(&exists)
	if err != nil || !exists {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}

	// Build dynamic update
	if req.APIKey != nil {
		isConfigured := *req.APIKey != ""
		_, err := h.db.Pool.Exec(r.Context(),
			`UPDATE ai_providers SET api_key = $1, is_configured = $2, updated_at = NOW() WHERE id = $3`,
			*req.APIKey, isConfigured, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update api_key")
			return
		}
	}

	if req.IsEnabled != nil {
		_, err := h.db.Pool.Exec(r.Context(),
			`UPDATE ai_providers SET is_enabled = $1, updated_at = NOW() WHERE id = $2`,
			*req.IsEnabled, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update is_enabled")
			return
		}
	}

	if req.Priority != nil {
		_, err := h.db.Pool.Exec(r.Context(),
			`UPDATE ai_providers SET priority = $1, updated_at = NOW() WHERE id = $2`,
			*req.Priority, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update priority")
			return
		}
	}

	if req.Settings != nil {
		_, err := h.db.Pool.Exec(r.Context(),
			`UPDATE ai_providers SET settings = $1, updated_at = NOW() WHERE id = $2`,
			*req.Settings, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update settings")
			return
		}
	}

	if req.BaseURL != nil {
		_, err := h.db.Pool.Exec(r.Context(),
			`UPDATE ai_providers SET api_base_url = $1, updated_at = NOW() WHERE id = $2`,
			*req.BaseURL, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update base_url")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Fetch provider configuration from DB
	var (
		apiKey, apiBaseURL, sdkType string
		isLocal                     bool
	)
	err := h.db.Pool.QueryRow(r.Context(),
		`SELECT api_key, api_base_url, sdk_type, is_local
		 FROM ai_providers WHERE id = $1`, id,
	).Scan(&apiKey, &apiBaseURL, &sdkType, &isLocal)
	if err != nil {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}

	// Pick a default model for the test
	var testModel string
	err = h.db.Pool.QueryRow(r.Context(),
		`SELECT id FROM ai_models WHERE provider_id = $1 AND is_enabled = true LIMIT 1`, id,
	).Scan(&testModel)
	if err != nil {
		// Use a sensible fallback
		testModel = ""
	}

	// Create a temporary provider instance
	var p provider.Provider
	switch sdkType {
	case "anthropic":
		p = provider.NewAnthropicProvider(apiKey, testModel, 256)
	case "openai":
		p = provider.NewOpenAIProvider(apiKey, apiBaseURL, testModel, 256)
	case "openai_compatible":
		p = provider.NewOpenAIProvider(apiKey, apiBaseURL, testModel, 256)
	case "ollama":
		p = provider.NewOllamaProvider(apiBaseURL, testModel)
	default:
		p = provider.NewOpenAIProvider(apiKey, apiBaseURL, testModel, 256)
	}

	// Test with a simple chat completion
	resp, err := p.ChatCompletion(r.Context(), provider.ChatRequest{
		Model:     testModel,
		MaxTokens: 50,
		Messages: []provider.Message{
			{Role: "user", Content: "Say hello in one word."},
		},
	})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"model":    resp.Model,
		"response": resp.Content,
		"usage":    resp.Usage,
	})
}

func (h *Handler) handleSyncProviders(w http.ResponseWriter, r *http.Request) {
	providerCount, modelCount, err := provider.SyncFromModelsDev(r.Context(), h.db.Pool)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sync failed: "+err.Error())
		return
	}

	// Include cache info in response
	cacheExists, cacheSize, cacheModTime := provider.CatalogCacheInfo()
	cacheInfo := map[string]any{"exists": cacheExists}
	if cacheExists {
		cacheInfo["size_bytes"] = cacheSize
		cacheInfo["updated_at"] = cacheModTime.Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "synced",
		"providers": providerCount,
		"models":    modelCount,
		"cache":     cacheInfo,
	})
}

// --- Model handlers ---

func (h *Handler) handleListModels(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	providerID := q.Get("provider_id")
	family := q.Get("family")
	toolCall := q.Get("tool_call")
	reasoning := q.Get("reasoning")
	search := q.Get("search")

	query := `SELECT m.id, m.name, m.provider_id, p.name AS provider_name,
	                 m.family, m.tool_call, m.reasoning,
	                 m.context_window, m.cost_input, m.cost_output,
	                 m.open_weights, m.is_enabled, m.max_output
	          FROM ai_models m
	          JOIN ai_providers p ON p.id = m.provider_id
	          WHERE 1=1`
	args := []any{}
	argIdx := 1

	if providerID != "" {
		query += fmt.Sprintf(" AND m.provider_id = $%d", argIdx)
		args = append(args, providerID)
		argIdx++
	}
	if family != "" {
		query += fmt.Sprintf(" AND m.family = $%d", argIdx)
		args = append(args, family)
		argIdx++
	}
	if toolCall == "true" {
		query += " AND m.tool_call = true"
	}
	if reasoning == "true" {
		query += " AND m.reasoning = true"
	}
	if search != "" {
		query += fmt.Sprintf(" AND m.name ILIKE $%d", argIdx)
		args = append(args, "%"+search+"%")
		argIdx++
	}

	query += " ORDER BY p.name, m.family, m.name"

	rows, err := h.db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query models")
		return
	}
	defer rows.Close()

	var models []map[string]any
	for rows.Next() {
		var (
			mID, mName, mProviderID, mProviderName, mFamily string
			mToolCall, mReasoning                            bool
			ctxWindow                                        int
			costIn, costOut                                  float64
			openWeights, mEnabled                            bool
			maxOutput                                        int
		)
		if err := rows.Scan(
			&mID, &mName, &mProviderID, &mProviderName,
			&mFamily, &mToolCall, &mReasoning,
			&ctxWindow, &costIn, &costOut,
			&openWeights, &mEnabled, &maxOutput,
		); err != nil {
			continue
		}
		models = append(models, map[string]any{
			"id":             mID,
			"name":           mName,
			"provider_id":    mProviderID,
			"provider_name":  mProviderName,
			"family":         mFamily,
			"tool_call":      mToolCall,
			"reasoning":      mReasoning,
			"context_window": ctxWindow,
			"cost_input":     costIn,
			"cost_output":    costOut,
			"open_weights":   openWeights,
			"is_enabled":     mEnabled,
			"max_output":     maxOutput,
		})
	}

	if models == nil {
		models = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

// --- Preference handlers ---

func (h *Handler) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT pr.key, pr.provider_id, pr.model_id, pr.settings,
		        p.name AS provider_name
		 FROM ai_preferences pr
		 JOIN ai_providers p ON p.id = pr.provider_id
		 ORDER BY pr.key`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query preferences")
		return
	}
	defer rows.Close()

	preferences := make(map[string]any)
	for rows.Next() {
		var (
			key, providerID, modelID string
			settings                 json.RawMessage
			providerName             string
		)
		if err := rows.Scan(&key, &providerID, &modelID, &settings, &providerName); err != nil {
			continue
		}
		preferences[key] = map[string]any{
			"provider_id":   providerID,
			"model_id":      modelID,
			"provider_name": providerName,
			"settings":      settings,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"preferences": preferences})
}

func (h *Handler) handleUpdatePreferences(w http.ResponseWriter, r *http.Request) {
	var req map[string]struct {
		ProviderID string           `json:"provider_id"`
		ModelID    string           `json:"model_id"`
		Settings   *json.RawMessage `json:"settings"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for key, pref := range req {
		// Validate key
		switch key {
		case "default", "planner", "executor", "reviewer", "embedding":
			// valid
		default:
			writeError(w, http.StatusBadRequest, "invalid preference key: "+key)
			return
		}

		settings := json.RawMessage("{}")
		if pref.Settings != nil {
			settings = *pref.Settings
		}

		_, err := h.db.Pool.Exec(r.Context(),
			`INSERT INTO ai_preferences (key, provider_id, model_id, settings, updated_at)
			 VALUES ($1, $2, $3, $4, NOW())
			 ON CONFLICT (key) DO UPDATE SET
			   provider_id = $2, model_id = $3, settings = $4, updated_at = NOW()`,
			key, pref.ProviderID, pref.ModelID, settings,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update preference: "+key)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// --- Setup handlers ---

func (h *Handler) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check setup_completed
	var setupCompleted json.RawMessage
	err := h.db.Pool.QueryRow(ctx,
		`SELECT value FROM setup_state WHERE key = 'setup_completed'`,
	).Scan(&setupCompleted)
	if err != nil {
		// Table may not exist yet
		writeJSON(w, http.StatusOK, map[string]any{
			"setup_completed":      false,
			"providers_configured": 0,
			"models_synced":        false,
		})
		return
	}

	// Count configured providers
	var configuredCount int
	_ = h.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ai_providers WHERE is_configured = true`,
	).Scan(&configuredCount)

	// Check models_last_synced
	var modelsSynced json.RawMessage
	_ = h.db.Pool.QueryRow(ctx,
		`SELECT value FROM setup_state WHERE key = 'models_last_synced'`,
	).Scan(&modelsSynced)

	isSynced := string(modelsSynced) != "" && string(modelsSynced) != "null" && string(modelsSynced) != `"null"`
	isCompleted := string(setupCompleted) == "true" || string(setupCompleted) == `"true"`

	writeJSON(w, http.StatusOK, map[string]any{
		"setup_completed":      isCompleted,
		"providers_configured": configuredCount,
		"models_synced":        isSynced,
	})
}

func (h *Handler) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	_, err := h.db.Pool.Exec(r.Context(),
		`INSERT INTO setup_state (key, value, updated_at)
		 VALUES ('setup_completed', 'true', NOW())
		 ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = NOW()`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mark setup as complete")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "setup_completed"})
}

