package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	modelsDevURL     = "https://models.dev/api.json"
	catalogCacheDir  = "data/catalog"
	catalogCacheFile = "models.dev.json"
)

// CatalogProvider represents a provider from models.dev.
type CatalogProvider struct {
	ID     string                  `json:"id"`
	Name   string                  `json:"name"`
	Env    []string                `json:"env"`
	NPM    string                  `json:"npm"`
	API    string                  `json:"api"`
	Doc    string                  `json:"doc"`
	Models map[string]CatalogModel `json:"models"`
}

// CatalogModel represents a model from the models.dev catalog.
type CatalogModel struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Family      string      `json:"family"`
	Attachment  bool        `json:"attachment"`
	Reasoning   bool        `json:"reasoning"`
	ToolCall    bool        `json:"tool_call"`
	Temperature bool        `json:"temperature"`
	Knowledge   string      `json:"knowledge"`
	ReleaseDate string      `json:"release_date"`
	OpenWeights bool        `json:"open_weights"`
	Modalities  *Modalities `json:"modalities"`
	Cost        *CostInfo   `json:"cost"`
	Limit       *LimitInfo  `json:"limit"`
}

// Modalities represents input/output modality capabilities.
type Modalities struct {
	Input  []string `json:"input"`
	Output []string `json:"output"`
}

// CostInfo represents per-million-token cost information.
type CostInfo struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cache_read"`
	CacheWrite float64 `json:"cache_write"`
}

// LimitInfo represents context and output token limits.
type LimitInfo struct {
	Context int `json:"context"`
	Output  int `json:"output"`
}

// DetectSDKType determines the SDK type from the npm package name.
func DetectSDKType(npm string) string {
	lower := strings.ToLower(npm)
	switch {
	case strings.Contains(lower, "anthropic"):
		return "anthropic"
	case strings.Contains(lower, "ollama"):
		return "ollama"
	case strings.Contains(lower, "openai"):
		return "openai_compatible"
	default:
		return "openai_compatible"
	}
}

// catalogCachePath returns the full path for the catalog cache file.
func catalogCachePath() string {
	return filepath.Join(catalogCacheDir, catalogCacheFile)
}

// saveCatalogCache writes the raw JSON to the local cache file.
func saveCatalogCache(data []byte) {
	if err := os.MkdirAll(catalogCacheDir, 0755); err != nil {
		slog.Warn("failed to create catalog cache dir", "error", err)
		return
	}
	if err := os.WriteFile(catalogCachePath(), data, 0644); err != nil {
		slog.Warn("failed to write catalog cache", "error", err)
		return
	}
	slog.Info("catalog cache saved", "path", catalogCachePath(), "size_kb", len(data)/1024)
}

// LoadCatalogCache reads the cached catalog JSON from disk.
// Returns nil if no cache exists.
func LoadCatalogCache() (map[string]CatalogProvider, error) {
	data, err := os.ReadFile(catalogCachePath())
	if err != nil {
		return nil, err
	}
	var catalog map[string]CatalogProvider
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("parsing cached catalog: %w", err)
	}
	return catalog, nil
}

// CatalogCacheInfo returns info about the cache file (exists, size, modified time).
func CatalogCacheInfo() (exists bool, sizeBytes int64, modTime time.Time) {
	info, err := os.Stat(catalogCachePath())
	if err != nil {
		return false, 0, time.Time{}
	}
	return true, info.Size(), info.ModTime()
}

// SyncFromModelsDev fetches the models.dev catalog, saves it to the local cache,
// and upserts into the database. Returns (providerCount, modelCount, error).
func SyncFromModelsDev(ctx context.Context, pool *pgxpool.Pool) (int, int, error) {
	// 1. Fetch catalog JSON
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsDevURL, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "PhantomStrike/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("fetching models.dev catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, 0, fmt.Errorf("models.dev returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("reading response body: %w", err)
	}

	// 2. Save raw JSON to local cache file (data/catalog/models.dev.json)
	saveCatalogCache(body)

	// 3. Parse JSON
	var catalog map[string]CatalogProvider
	if err := json.Unmarshal(body, &catalog); err != nil {
		return 0, 0, fmt.Errorf("parsing catalog JSON: %w", err)
	}

	providerCount := 0
	modelCount := 0

	// 3. Upsert providers and models
	for providerID, cp := range catalog {
		sdkType := DetectSDKType(cp.NPM)

		// Determine env var name
		envVar := ""
		if len(cp.Env) > 0 {
			envVar = cp.Env[0]
		}

		// Determine if this is a local provider
		isLocal := sdkType == "ollama"

		displayName := cp.Name
		if displayName == "" {
			displayName = providerID
		}

		apiBaseURL := cp.API
		if apiBaseURL == "" {
			// Well-known provider defaults
			knownURLs := map[string]string{
				"anthropic":  "https://api.anthropic.com",
				"openai":     "https://api.openai.com/v1",
				"groq":       "https://api.groq.com/openai/v1",
				"deepseek":   "https://api.deepseek.com/v1",
				"mistral":    "https://api.mistral.ai/v1",
				"cohere":     "https://api.cohere.ai/v1",
				"together":   "https://api.together.xyz/v1",
				"fireworks":  "https://api.fireworks.ai/inference/v1",
				"perplexity": "https://api.perplexity.ai",
				"openrouter": "https://openrouter.ai/api/v1",
			}
			if url, ok := knownURLs[providerID]; ok {
				apiBaseURL = url
			}
		}
		if apiBaseURL == "" {
			// Use preset base URL if available
			if preset, ok := OpenAICompatiblePresets[providerID]; ok {
				apiBaseURL = preset.DefaultBaseURL
			}
		}

		docURL := cp.Doc

		// UPSERT provider: don't overwrite user-configured fields
		_, err := pool.Exec(ctx,
			`INSERT INTO ai_providers (id, name, api_base_url, env_var, sdk_type, doc_url, is_local, synced_from, last_synced_at, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, 'models.dev', NOW(), NOW(), NOW())
			 ON CONFLICT (id) DO UPDATE SET
			   name = EXCLUDED.name,
			   api_base_url = CASE WHEN ai_providers.api_base_url = '' THEN EXCLUDED.api_base_url ELSE ai_providers.api_base_url END,
			   env_var = CASE WHEN ai_providers.env_var = '' THEN EXCLUDED.env_var ELSE ai_providers.env_var END,
			   sdk_type = EXCLUDED.sdk_type,
			   doc_url = EXCLUDED.doc_url,
			   is_local = EXCLUDED.is_local,
			   synced_from = 'models.dev',
			   last_synced_at = NOW(),
			   updated_at = NOW()`,
			providerID, displayName, apiBaseURL, envVar, sdkType, docURL, isLocal,
		)
		if err != nil {
			slog.Warn("failed to upsert provider", "id", providerID, "error", err)
			continue
		}
		providerCount++

		// Upsert models
		for modelID, cm := range cp.Models {
			contextWindow := 0
			maxOutput := 0
			if cm.Limit != nil {
				contextWindow = cm.Limit.Context
				maxOutput = cm.Limit.Output
			}

			costInput := 0.0
			costOutput := 0.0
			costCacheRead := 0.0
			costCacheWrite := 0.0
			if cm.Cost != nil {
				costInput = cm.Cost.Input
				costOutput = cm.Cost.Output
				costCacheRead = cm.Cost.CacheRead
				costCacheWrite = cm.Cost.CacheWrite
			}

			var inputModalities, outputModalities []string
			if cm.Modalities != nil {
				inputModalities = cm.Modalities.Input
				outputModalities = cm.Modalities.Output
			}
			if len(inputModalities) == 0 {
				inputModalities = []string{"text"}
			}
			if len(outputModalities) == 0 {
				outputModalities = []string{"text"}
			}

			modelName := cm.Name
			if modelName == "" {
				modelName = modelID
			}

			family := cm.Family

			var releaseDate *time.Time
			if cm.ReleaseDate != "" {
				if t, err := time.Parse("2006-01-02", cm.ReleaseDate); err == nil {
					releaseDate = &t
				}
			}

			_, err := pool.Exec(ctx,
				`INSERT INTO ai_models (
					id, provider_id, name, family,
					tool_call, reasoning, attachment, temperature,
					input_modalities, output_modalities,
					context_window, max_output,
					cost_input, cost_output, cost_cache_read, cost_cache_write,
					knowledge_cutoff, release_date, open_weights,
					synced_from, last_synced_at, created_at, updated_at
				) VALUES (
					$1, $2, $3, $4,
					$5, $6, $7, $8,
					$9, $10,
					$11, $12,
					$13, $14, $15, $16,
					$17, $18, $19,
					'models.dev', NOW(), NOW(), NOW()
				)
				ON CONFLICT (id, provider_id) DO UPDATE SET
					name = EXCLUDED.name,
					family = EXCLUDED.family,
					tool_call = EXCLUDED.tool_call,
					reasoning = EXCLUDED.reasoning,
					attachment = EXCLUDED.attachment,
					temperature = EXCLUDED.temperature,
					input_modalities = EXCLUDED.input_modalities,
					output_modalities = EXCLUDED.output_modalities,
					context_window = EXCLUDED.context_window,
					max_output = EXCLUDED.max_output,
					cost_input = EXCLUDED.cost_input,
					cost_output = EXCLUDED.cost_output,
					cost_cache_read = EXCLUDED.cost_cache_read,
					cost_cache_write = EXCLUDED.cost_cache_write,
					knowledge_cutoff = EXCLUDED.knowledge_cutoff,
					release_date = EXCLUDED.release_date,
					open_weights = EXCLUDED.open_weights,
					synced_from = 'models.dev',
					last_synced_at = NOW(),
					updated_at = NOW()`,
				modelID, providerID, modelName, family,
				cm.ToolCall, cm.Reasoning, cm.Attachment, cm.Temperature,
				inputModalities, outputModalities,
				contextWindow, maxOutput,
				costInput, costOutput, costCacheRead, costCacheWrite,
				cm.Knowledge, releaseDate, cm.OpenWeights,
			)
			if err != nil {
				slog.Warn("failed to upsert model", "id", modelID, "provider", providerID, "error", err)
				continue
			}
			modelCount++
		}
	}

	// 4. Update setup_state.models_last_synced
	_, err = pool.Exec(ctx,
		`INSERT INTO setup_state (key, value, updated_at)
		 VALUES ('models_last_synced', to_jsonb(NOW()::text), NOW())
		 ON CONFLICT (key) DO UPDATE SET value = to_jsonb(NOW()::text), updated_at = NOW()`)
	if err != nil {
		slog.Warn("failed to update models_last_synced", "error", err)
	}

	slog.Info("models.dev sync completed",
		"providers", providerCount,
		"models", modelCount,
	)

	return providerCount, modelCount, nil
}
