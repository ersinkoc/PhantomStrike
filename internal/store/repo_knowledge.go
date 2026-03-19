package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// KnowledgeItem represents a knowledge base entry with embedding
type KnowledgeItem struct {
	ID          uuid.UUID       `json:"id"`
	Category    string          `json:"category"`
	Title       string          `json:"title"`
	Content     string          `json:"content"`
	SourceFile  string          `json:"source_file"`
	ChunkIndex  int             `json:"chunk_index"`
	Embedding   []float32       `json:"embedding,omitempty"`
	Metadata    JSONB           `json:"metadata"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
	UpdatedAt   pgtype.Timestamptz `json:"updated_at"`
}

// CreateKnowledgeItem creates a new knowledge entry
func (db *DB) CreateKnowledgeItem(ctx context.Context, k *KnowledgeItem) error {
	query := `
		INSERT INTO knowledge_items (category, title, content, source_file, chunk_index, embedding, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`

	return db.Pool.QueryRow(ctx, query,
		k.Category, k.Title, k.Content, k.SourceFile, k.ChunkIndex, k.Embedding, k.Metadata,
	).Scan(&k.ID, &k.CreatedAt, &k.UpdatedAt)
}

// GetKnowledgeItem retrieves a knowledge item by ID
func (db *DB) GetKnowledgeItem(ctx context.Context, id uuid.UUID) (*KnowledgeItem, error) {
	query := `
		SELECT id, category, title, content, source_file, chunk_index, metadata, created_at, updated_at
		FROM knowledge_items WHERE id = $1`

	k := &KnowledgeItem{}
	err := db.Pool.QueryRow(ctx, query, id).Scan(
		&k.ID, &k.Category, &k.Title, &k.Content, &k.SourceFile,
		&k.ChunkIndex, &k.Metadata, &k.CreatedAt, &k.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying knowledge item: %w", err)
	}
	return k, nil
}

// ListKnowledgeItems lists knowledge items with filtering
func (db *DB) ListKnowledgeItems(ctx context.Context, category string, limit, offset int) ([]*KnowledgeItem, int64, error) {
	whereClause := ""
	args := []interface{}{}
	argIdx := 1

	if category != "" {
		whereClause = fmt.Sprintf("WHERE category = $%d", argIdx)
		args = append(args, category)
		argIdx++
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM knowledge_items " + whereClause
	var total int64
	if err := db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting knowledge items: %w", err)
	}

	// Query
	query := fmt.Sprintf(`
		SELECT id, category, title, content, source_file, chunk_index, metadata, created_at, updated_at
		FROM knowledge_items %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying knowledge items: %w", err)
	}
	defer rows.Close()

	var items []*KnowledgeItem
	for rows.Next() {
		k := &KnowledgeItem{}
		if err := rows.Scan(
			&k.ID, &k.Category, &k.Title, &k.Content, &k.SourceFile,
			&k.ChunkIndex, &k.Metadata, &k.CreatedAt, &k.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning knowledge item: %w", err)
		}
		items = append(items, k)
	}

	return items, total, rows.Err()
}

// SearchKnowledgeByVector performs semantic search using vector similarity
func (db *DB) SearchKnowledgeByVector(ctx context.Context, embedding []float32, limit int) ([]*KnowledgeItem, error) {
	query := `
		SELECT id, category, title, content, source_file, chunk_index, metadata,
		       1 - (embedding <=> $1) as similarity
		FROM knowledge_items
		WHERE embedding IS NOT NULL
		ORDER BY embedding <=> $1
		LIMIT $2`

	rows, err := db.Pool.Query(ctx, query, embedding, limit)
	if err != nil {
		return nil, fmt.Errorf("searching knowledge by vector: %w", err)
	}
	defer rows.Close()

	var items []*KnowledgeItem
	for rows.Next() {
		k := &KnowledgeItem{}
		var similarity float64
		if err := rows.Scan(
			&k.ID, &k.Category, &k.Title, &k.Content, &k.SourceFile,
			&k.ChunkIndex, &k.Metadata, &similarity,
		); err != nil {
			return nil, fmt.Errorf("scanning knowledge item: %w", err)
		}
		// Store similarity in metadata
		if k.Metadata == nil {
			k.Metadata = make(JSONB)
		}
		k.Metadata["similarity"] = similarity
		items = append(items, k)
	}

	return items, rows.Err()
}

// SearchKnowledgeByText performs full-text search
func (db *DB) SearchKnowledgeByText(ctx context.Context, searchTerm string, limit int) ([]*KnowledgeItem, error) {
	query := `
		SELECT id, category, title, content, source_file, chunk_index, metadata,
		       ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', $1)) as rank
		FROM knowledge_items
		WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', $1)
		ORDER BY rank DESC
		LIMIT $2`

	rows, err := db.Pool.Query(ctx, query, searchTerm, limit)
	if err != nil {
		return nil, fmt.Errorf("searching knowledge by text: %w", err)
	}
	defer rows.Close()

	var items []*KnowledgeItem
	for rows.Next() {
		k := &KnowledgeItem{}
		var rank float64
		if err := rows.Scan(
			&k.ID, &k.Category, &k.Title, &k.Content, &k.SourceFile,
			&k.ChunkIndex, &k.Metadata, &rank,
		); err != nil {
			return nil, fmt.Errorf("scanning knowledge item: %w", err)
		}
		if k.Metadata == nil {
			k.Metadata = make(JSONB)
		}
		k.Metadata["rank"] = rank
		items = append(items, k)
	}

	return items, rows.Err()
}

// HybridSearchKnowledge combines vector and text search
func (db *DB) HybridSearchKnowledge(ctx context.Context, embedding []float32, searchTerm string, limit int, vectorWeight float64) ([]*KnowledgeItem, error) {
	// Get vector results
	vectorResults, err := db.SearchKnowledgeByVector(ctx, embedding, limit)
	if err != nil {
		return nil, err
	}

	// Get text results
	textResults, err := db.SearchKnowledgeByText(ctx, searchTerm, limit)
	if err != nil {
		return nil, err
	}

	// Merge and deduplicate with weighted scores
	seen := make(map[uuid.UUID]*KnowledgeItem)

	for _, item := range vectorResults {
		sim, _ := item.Metadata["similarity"].(float64)
		item.Metadata["hybrid_score"] = sim * vectorWeight
		seen[item.ID] = item
	}

	for _, item := range textResults {
		rank, _ := item.Metadata["rank"].(float64)
		if existing, ok := seen[item.ID]; ok {
			existingScore, _ := existing.Metadata["hybrid_score"].(float64)
			existing.Metadata["hybrid_score"] = existingScore + rank*(1-vectorWeight)
		} else {
			item.Metadata["hybrid_score"] = rank * (1 - vectorWeight)
			seen[item.ID] = item
		}
	}

	// Convert to slice and sort by hybrid score
	results := make([]*KnowledgeItem, 0, len(seen))
	for _, item := range seen {
		results = append(results, item)
	}

	// Simple bubble sort by hybrid_score
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			scoreI, _ := results[i].Metadata["hybrid_score"].(float64)
			scoreJ, _ := results[j].Metadata["hybrid_score"].(float64)
			if scoreJ > scoreI {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// DeleteKnowledgeItem deletes a knowledge item
func (db *DB) DeleteKnowledgeItem(ctx context.Context, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, "DELETE FROM knowledge_items WHERE id = $1", id)
	return err
}

// DeleteKnowledgeBySource deletes all items from a source file
func (db *DB) DeleteKnowledgeBySource(ctx context.Context, sourceFile string) error {
	_, err := db.Pool.Exec(ctx, "DELETE FROM knowledge_items WHERE source_file = $1", sourceFile)
	return err
}

// ListKnowledgeCategories returns distinct categories
func (db *DB) ListKnowledgeCategories(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT category FROM knowledge_items ORDER BY category`

	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("querying categories: %w", err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var cat string
		if err := rows.Scan(&cat); err != nil {
			return nil, fmt.Errorf("scanning category: %w", err)
		}
		categories = append(categories, cat)
	}

	return categories, rows.Err()
}
