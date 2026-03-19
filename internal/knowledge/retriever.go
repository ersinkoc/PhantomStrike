package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

// SearchResult represents a knowledge base search result.
type SearchResult struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Content  string  `json:"content"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
}

// Retriever provides hybrid search over the knowledge base (vector + full-text).
type Retriever struct {
	pool   *pgxpool.Pool
	cfg    config.RetrievalConfig
}

// NewRetriever creates a new knowledge retriever.
func NewRetriever(pool *pgxpool.Pool, cfg config.RetrievalConfig) *Retriever {
	return &Retriever{pool: pool, cfg: cfg}
}

// Search performs a hybrid search combining full-text search with optional vector similarity.
func (r *Retriever) Search(ctx context.Context, query string, category string) ([]SearchResult, error) {
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}

	// Full-text search with ts_rank
	sql := `
		SELECT id, title, content, category,
			ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', $1)) as score
		FROM knowledge_items
		WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', $1)
	`
	args := []any{query}
	argIdx := 2

	if category != "" {
		sql += fmt.Sprintf(" AND category = $%d", argIdx)
		args = append(args, category)
		argIdx++
	}

	sql += fmt.Sprintf(" ORDER BY score DESC LIMIT $%d", argIdx)
	args = append(args, r.cfg.TopK)

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var sr SearchResult
		if err := rows.Scan(&sr.ID, &sr.Title, &sr.Content, &sr.Category, &sr.Score); err != nil {
			slog.Warn("scanning search result", "error", err)
			continue
		}
		results = append(results, sr)
	}

	return results, nil
}

// GetByCategory returns all knowledge items in a category.
func (r *Retriever) GetByCategory(ctx context.Context, category string) ([]SearchResult, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, title, content, category, 1.0 as score FROM knowledge_items WHERE category = $1 ORDER BY title`,
		category,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var sr SearchResult
		if err := rows.Scan(&sr.ID, &sr.Title, &sr.Content, &sr.Category, &sr.Score); err != nil {
			continue
		}
		results = append(results, sr)
	}
	return results, nil
}

// Categories returns all distinct categories.
func (r *Retriever) Categories(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, "SELECT DISTINCT category FROM knowledge_items ORDER BY category")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cats []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			continue
		}
		cats = append(cats, cat)
	}
	return cats, nil
}

// Ingest adds a knowledge item to the database.
func (r *Retriever) Ingest(ctx context.Context, category, title, content, sourceFile string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO knowledge_items (category, title, content, source_file) VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		category, title, strings.TrimSpace(content), sourceFile,
	)
	return err
}
