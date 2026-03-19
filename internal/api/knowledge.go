package api

import (
	"net/http"
	"strconv"

	"github.com/ersinkoc/phantomstrike/internal/auth"
)

// handleKnowledgeList returns knowledge items with optional search
func (h *Handler) handleKnowledgeList(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	search := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")

	var query string
	var args []interface{}

	if search != "" {
		query = `SELECT id, category, title, content, source_file, embedding_model, created_at
			 FROM knowledge_items
			 WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', $1)
			 ORDER BY ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', $1)) DESC
			 LIMIT $2`
		args = []interface{}{search, limit}
	} else if category != "" {
		query = `SELECT id, category, title, content, source_file, embedding_model, created_at
			 FROM knowledge_items WHERE category = $1 ORDER BY title LIMIT $2`
		args = []interface{}{category, limit}
	} else {
		query = `SELECT id, category, title, content, source_file, embedding_model, created_at
			 FROM knowledge_items ORDER BY category, title LIMIT $1`
		args = []interface{}{limit}
	}

	rows, err := h.db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var id, category, title, content, sourceFile, embeddingModel string
		var createdAt string
		if err := rows.Scan(&id, &category, &title, &content, &sourceFile, &embeddingModel, &createdAt); err != nil {
			continue
		}
		items = append(items, map[string]interface{}{
			"id":              id,
			"category":        category,
			"title":           title,
			"content":         content,
			"source_file":     sourceFile,
			"embedding_model": embeddingModel,
			"created_at":      createdAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

// handleKnowledgeSearch performs semantic search
func (h *Handler) handleKnowledgeSearch(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Query    string `json:"query"`
		Category string `json:"category"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "query required")
		return
	}

	// Use full-text search for now (semantic search would require embeddings)
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, category, title, content, source_file,
			ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', $1)) as score
		 FROM knowledge_items
		 WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', $1)
		 ORDER BY score DESC LIMIT 10`,
		req.Query,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, category, title, content, sourceFile string
		var score float64
		if err := rows.Scan(&id, &category, &title, &content, &sourceFile, &score); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":          id,
			"category":    category,
			"title":       title,
			"content":     content,
			"source_file": sourceFile,
			"score":       score,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"results": results})
}

// handleKnowledgeCategories returns all categories
func (h *Handler) handleKnowledgeCategories(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(), "SELECT DISTINCT category FROM knowledge_items ORDER BY category")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			continue
		}
		categories = append(categories, cat)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"categories": categories})
}
