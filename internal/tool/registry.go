package tool

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/ersinkoc/phantomstrike/internal/store"
)

// Definition represents a parsed tool definition from YAML.
type Definition struct {
	Name             string       `yaml:"name" json:"name"`
	Version          string       `yaml:"version" json:"version"`
	Category         string       `yaml:"category" json:"category"`
	Phase            string       `yaml:"phase" json:"phase"` // recon, scanning, exploitation, post_exploit
	Tags             []string     `yaml:"tags" json:"tags"`
	Command          string       `yaml:"command" json:"command"`
	Args             []string     `yaml:"args" json:"args"`
	Docker           DockerDef    `yaml:"docker" json:"docker"`
	ShortDescription string       `yaml:"short_description" json:"short_description"`
	Description      string       `yaml:"description" json:"description"`
	Notes            string       `yaml:"notes" json:"notes"`
	Parameters       []ParamDef   `yaml:"parameters" json:"parameters"`
	Output           OutputDef    `yaml:"output" json:"output"`
	ChainSuggestions ChainDef     `yaml:"chain_suggestions" json:"chain_suggestions"`
	Requirements     RequireDef   `yaml:"requirements" json:"requirements"`
	Enabled          bool         `yaml:"enabled" json:"enabled"`
}

type DockerDef struct {
	Image       string `yaml:"image" json:"image"`
	Dockerfile  string `yaml:"dockerfile" json:"dockerfile"`
	Network     string `yaml:"network" json:"network"`
	MemoryLimit string `yaml:"memory_limit" json:"memory_limit"`
	CPULimit    string `yaml:"cpu_limit" json:"cpu_limit"`
	Timeout     string `yaml:"timeout" json:"timeout"`
}

type ParamDef struct {
	Name        string   `yaml:"name" json:"name"`
	Type        string   `yaml:"type" json:"type"`
	Description string   `yaml:"description" json:"description"`
	Required    bool     `yaml:"required" json:"required"`
	Flag        string   `yaml:"flag" json:"flag"`
	Default     any      `yaml:"default" json:"default,omitempty"`
	Validation  string   `yaml:"validation" json:"validation,omitempty"`
	Enum        []string `yaml:"enum" json:"enum,omitempty"`
	Min         *int     `yaml:"min" json:"min,omitempty"`
	Max         *int     `yaml:"max" json:"max,omitempty"`
}

type OutputDef struct {
	Format             string            `yaml:"format" json:"format"`
	SuccessPatterns    []string          `yaml:"success_patterns" json:"success_patterns"`
	FailurePatterns    []string          `yaml:"failure_patterns" json:"failure_patterns"`
	SeverityIndicators map[string][]string `yaml:"severity_indicators" json:"severity_indicators"`
}

type ChainDef struct {
	Before []string `yaml:"before" json:"before"`
	After  []string `yaml:"after" json:"after"`
}

type RequireDef struct {
	Tools           []string `yaml:"tools" json:"tools"`
	DockerAvailable bool     `yaml:"docker_available" json:"docker_available"`
}

// Registry manages tool definitions with hot-reload support.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*Definition
	dir   string
	db    *store.DB
}

// NewRegistry creates a new tool registry.
func NewRegistry(dir string, db *store.DB) *Registry {
	return &Registry{
		tools: make(map[string]*Definition),
		dir:   dir,
		db:    db,
	}
}

// LoadAll scans the tools directory and loads all YAML definitions.
func (r *Registry) LoadAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := 0
	err := filepath.WalkDir(r.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		// Skip docker directory
		if filepath.Base(filepath.Dir(path)) == "_docker" {
			return nil
		}

		def, err := ParseToolFile(path)
		if err != nil {
			slog.Warn("failed to parse tool definition", "path", path, "error", err)
			return nil
		}

		r.tools[def.Name] = def
		count++
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking tools dir: %w", err)
	}

	slog.Info("loaded tool definitions", "count", count, "dir", r.dir)
	return nil
}

// SyncToDB syncs all loaded tool definitions to the database tool_registry table.
func (r *Registry) SyncToDB(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, def := range r.tools {
		_, err := r.db.Pool.Exec(ctx,
			`INSERT INTO tool_registry (name, category, definition, source, enabled)
			 VALUES ($1, $2, $3, 'builtin', $4)
			 ON CONFLICT (name) DO UPDATE SET category = $2, definition = $3, updated_at = NOW()`,
			def.Name, def.Category, def, def.Enabled,
		)
		if err != nil {
			slog.Warn("failed to sync tool to DB", "tool", def.Name, "error", err)
		}
	}
	return nil
}

// Get returns a tool definition by name.
func (r *Registry) Get(name string) (*Definition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.tools[name]
	return def, ok
}

// List returns all tool definitions.
func (r *Registry) List() []*Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Definition, 0, len(r.tools))
	for _, def := range r.tools {
		result = append(result, def)
	}
	return result
}

// ListByCategory returns tools filtered by category prefix.
func (r *Registry) ListByCategory(category string) []*Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*Definition
	for _, def := range r.tools {
		if def.Category == category {
			result = append(result, def)
		}
	}
	return result
}

// ToMCPTools converts tool definitions to MCP-compatible tool schemas.
func (r *Registry) ToMCPTools() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var tools []map[string]any
	for _, def := range r.tools {
		if !def.Enabled {
			continue
		}

		properties := make(map[string]any)
		var required []string
		for _, p := range def.Parameters {
			prop := map[string]any{
				"type":        p.Type,
				"description": p.Description,
			}
			if len(p.Enum) > 0 {
				prop["enum"] = p.Enum
			}
			if p.Default != nil {
				prop["default"] = p.Default
			}
			properties[p.Name] = prop
			if p.Required {
				required = append(required, p.Name)
			}
		}

		tools = append(tools, map[string]any{
			"name":        def.Name,
			"description": def.ShortDescription,
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": properties,
				"required":   required,
			},
		})
	}
	return tools
}
