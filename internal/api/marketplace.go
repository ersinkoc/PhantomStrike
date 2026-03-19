package api

import (
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// handleListMarketplaceTools returns tools from the tool registry for the marketplace
func (h *Handler) handleListMarketplaceTools(w http.ResponseWriter, r *http.Request) {
	defs := h.registry.List()

	var tools []map[string]any
	for _, def := range defs {
		tools = append(tools, map[string]any{
			"name":              def.Name,
			"version":           def.Version,
			"category":          def.Category,
			"phase":             def.Phase,
			"tags":              def.Tags,
			"short_description": def.ShortDescription,
			"description":       def.Description,
			"enabled":           def.Enabled,
			"parameters":        def.Parameters,
			"docker":            def.Docker,
			"requirements":      def.Requirements,
		})
	}

	if tools == nil {
		tools = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

// handleListMarketplaceSkills reads skills from the skills directory and returns them for the marketplace
func (h *Handler) handleListMarketplaceSkills(w http.ResponseWriter, r *http.Request) {
	skillsDir := h.cfg.Skills.Dir
	if skillsDir == "" {
		skillsDir = "skills"
	}

	var skills []map[string]interface{}

	err := filepath.Walk(skillsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var skill map[string]interface{}
		if err := yaml.Unmarshal(data, &skill); err != nil {
			return nil
		}

		skills = append(skills, skill)
		return nil
	})

	if err != nil || skills == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"skills": []interface{}{}})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"skills": skills})
}
