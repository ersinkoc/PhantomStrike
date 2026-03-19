package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// handleListRoles returns role definitions from roles/ directory
func (h *Handler) handleListRoles(w http.ResponseWriter, r *http.Request) {
	// Check cache first
	if h.cache != nil {
		var cached map[string]any
		if err := h.cache.GetJSON(r.Context(), "api:roles:list", &cached); err == nil {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

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

	result := map[string]interface{}{"roles": roles}

	// Cache the result
	if h.cache != nil {
		_ = h.cache.SetJSON(r.Context(), "api:roles:list", result, 5*time.Minute)
	}

	writeJSON(w, http.StatusOK, result)
}

// handleListSkills returns skill definitions from skills/ directory
func (h *Handler) handleListSkills(w http.ResponseWriter, r *http.Request) {
	// Check cache first
	if h.cache != nil {
		var cached map[string]any
		if err := h.cache.GetJSON(r.Context(), "api:skills:list", &cached); err == nil {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

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

	result := map[string]interface{}{"skills": skills}

	// Cache the result
	if h.cache != nil {
		_ = h.cache.SetJSON(r.Context(), "api:skills:list", result, 5*time.Minute)
	}

	writeJSON(w, http.StatusOK, result)
}

// --- Roles CRUD ---

// handleCreateRole creates a new role YAML file.
func (h *Handler) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	rolesDir := h.cfg.Roles.Dir
	if rolesDir == "" {
		rolesDir = "roles"
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Validate YAML
	var role map[string]interface{}
	if err := yaml.Unmarshal(body, &role); err != nil {
		writeError(w, http.StatusBadRequest, "invalid YAML body")
		return
	}

	name, _ := role["name"].(string)
	if name == "" {
		writeError(w, http.StatusBadRequest, "role name is required")
		return
	}

	// Sanitize filename
	filename := sanitizeFilename(name) + ".yaml"
	filePath := filepath.Join(rolesDir, filename)

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		writeError(w, http.StatusConflict, "role already exists")
		return
	}

	// Ensure directory exists
	if err := os.MkdirAll(rolesDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create roles directory")
		return
	}

	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write role file")
		return
	}

	// Invalidate cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:roles:list")
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "name": name})
}

// handleUpdateRole updates an existing role YAML file.
func (h *Handler) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "role name is required")
		return
	}

	rolesDir := h.cfg.Roles.Dir
	if rolesDir == "" {
		rolesDir = "roles"
	}

	filePath := filepath.Join(rolesDir, sanitizeFilename(name)+".yaml")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Validate YAML
	var role map[string]interface{}
	if err := yaml.Unmarshal(body, &role); err != nil {
		writeError(w, http.StatusBadRequest, "invalid YAML body")
		return
	}

	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write role file")
		return
	}

	// Invalidate cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:roles:list")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// handleDeleteRole removes a role YAML file.
func (h *Handler) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "role name is required")
		return
	}

	rolesDir := h.cfg.Roles.Dir
	if rolesDir == "" {
		rolesDir = "roles"
	}

	filePath := filepath.Join(rolesDir, sanitizeFilename(name)+".yaml")

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}

	if err := os.Remove(filePath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete role file")
		return
	}

	// Invalidate cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:roles:list")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Skills CRUD ---

// handleCreateSkill creates a new skill YAML file.
func (h *Handler) handleCreateSkill(w http.ResponseWriter, r *http.Request) {
	skillsDir := h.cfg.Skills.Dir
	if skillsDir == "" {
		skillsDir = "skills"
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Validate YAML
	var skill map[string]interface{}
	if err := yaml.Unmarshal(body, &skill); err != nil {
		writeError(w, http.StatusBadRequest, "invalid YAML body")
		return
	}

	name, _ := skill["name"].(string)
	if name == "" {
		writeError(w, http.StatusBadRequest, "skill name is required")
		return
	}

	// Sanitize filename
	filename := sanitizeFilename(name) + ".yaml"
	filePath := filepath.Join(skillsDir, filename)

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		writeError(w, http.StatusConflict, "skill already exists")
		return
	}

	// Ensure directory exists
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create skills directory")
		return
	}

	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write skill file")
		return
	}

	// Invalidate cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:skills:list")
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "name": name})
}

// handleUpdateSkill updates an existing skill YAML file.
func (h *Handler) handleUpdateSkill(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "skill name is required")
		return
	}

	skillsDir := h.cfg.Skills.Dir
	if skillsDir == "" {
		skillsDir = "skills"
	}

	filePath := filepath.Join(skillsDir, sanitizeFilename(name)+".yaml")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "skill not found")
		return
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Validate YAML
	var skill map[string]interface{}
	if err := yaml.Unmarshal(body, &skill); err != nil {
		writeError(w, http.StatusBadRequest, "invalid YAML body")
		return
	}

	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write skill file")
		return
	}

	// Invalidate cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:skills:list")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// handleDeleteSkill removes a skill YAML file.
func (h *Handler) handleDeleteSkill(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "skill name is required")
		return
	}

	skillsDir := h.cfg.Skills.Dir
	if skillsDir == "" {
		skillsDir = "skills"
	}

	filePath := filepath.Join(skillsDir, sanitizeFilename(name)+".yaml")

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "skill not found")
		return
	}

	if err := os.Remove(filePath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete skill file")
		return
	}

	// Invalidate cache
	if h.cache != nil {
		_ = h.cache.Delete(r.Context(), "api:skills:list")
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// sanitizeFilename converts a name to a safe filename by replacing
// non-alphanumeric characters with hyphens and lowercasing.
func sanitizeFilename(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	return name
}
