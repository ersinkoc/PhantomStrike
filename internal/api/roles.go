package api

import (
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// handleListRoles returns role definitions from roles/ directory
func (h *Handler) handleListRoles(w http.ResponseWriter, r *http.Request) {
	rolesDir := h.cfg.Roles.Dir
	if rolesDir == "" {
		rolesDir = "roles"
	}

	var roles []map[string]interface{}

	// Walk roles directory
	err := filepath.Walk(rolesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var role map[string]interface{}
		if err := yaml.Unmarshal(data, &role); err != nil {
			return nil
		}

		roles = append(roles, role)
		return nil
	})

	if err != nil {
		// Return empty list if directory doesn't exist
		writeJSON(w, http.StatusOK, map[string]interface{}{"roles": []interface{}{}})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"roles": roles})
}

// handleListSkills returns skill definitions from skills/ directory
func (h *Handler) handleListSkills(w http.ResponseWriter, r *http.Request) {
	skillsDir := h.cfg.Skills.Dir
	if skillsDir == "" {
		skillsDir = "skills"
	}

	var skills []map[string]interface{}

	// Walk skills directory
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

	if err != nil {
		// Return empty list if directory doesn't exist
		writeJSON(w, http.StatusOK, map[string]interface{}{"skills": []interface{}{}})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"skills": skills})
}
