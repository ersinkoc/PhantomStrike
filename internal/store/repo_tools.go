package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Tool represents a registered security tool
type Tool struct {
	ID            uuid.UUID       `json:"id"`
	Name          string          `json:"name"`
	Category      string          `json:"category"`
	Definition    JSONB           `json:"definition"`
	Source        string          `json:"source"`
	Enabled       bool            `json:"enabled"`
	InstallCount  int             `json:"install_count"`
	AvgExecTime   *int            `json:"avg_exec_time"`
	SuccessRate   *float64        `json:"success_rate"`
	LastUsed      *pgtype.Timestamptz `json:"last_used"`
	CreatedAt     pgtype.Timestamptz  `json:"created_at"`
	UpdatedAt     pgtype.Timestamptz  `json:"updated_at"`
}

// CreateTool creates a new tool entry
func (db *DB) CreateTool(ctx context.Context, t *Tool) error {
	query := `
		INSERT INTO tool_registry (name, category, definition, source, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`

	return db.Pool.QueryRow(ctx, query,
		t.Name, t.Category, t.Definition, t.Source, t.Enabled,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

// GetToolByName retrieves a tool by name
func (db *DB) GetToolByName(ctx context.Context, name string) (*Tool, error) {
	query := `
		SELECT id, name, category, definition, source, enabled,
		       install_count, avg_exec_time, success_rate, last_used, created_at, updated_at
		FROM tool_registry WHERE name = $1`

	t := &Tool{}
	err := db.Pool.QueryRow(ctx, query, name).Scan(
		&t.ID, &t.Name, &t.Category, &t.Definition, &t.Source, &t.Enabled,
		&t.InstallCount, &t.AvgExecTime, &t.SuccessRate, &t.LastUsed, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying tool: %w", err)
	}
	return t, nil
}

// ListTools lists tools with filtering
func (db *DB) ListTools(ctx context.Context, category string, enabledOnly bool) ([]*Tool, error) {
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if category != "" {
		whereClause += fmt.Sprintf(" AND category = $%d", argIdx)
		args = append(args, category)
		argIdx++
	}
	if enabledOnly {
		whereClause += " AND enabled = true"
	}

	query := fmt.Sprintf(`
		SELECT id, name, category, definition, source, enabled,
		       install_count, avg_exec_time, success_rate, last_used, created_at, updated_at
		FROM tool_registry %s
		ORDER BY category, name`, whereClause)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying tools: %w", err)
	}
	defer rows.Close()

	var tools []*Tool
	for rows.Next() {
		t := &Tool{}
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Category, &t.Definition, &t.Source, &t.Enabled,
			&t.InstallCount, &t.AvgExecTime, &t.SuccessRate, &t.LastUsed, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning tool: %w", err)
		}
		tools = append(tools, t)
	}

	return tools, rows.Err()
}

// ListToolCategories returns distinct categories
func (db *DB) ListToolCategories(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT category FROM tool_registry ORDER BY category`

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

// UpdateTool updates a tool
func (db *DB) UpdateTool(ctx context.Context, t *Tool) error {
	query := `
		UPDATE tool_registry
		SET category = $2, definition = $3, enabled = $4, source = $5
		WHERE name = $1`

	_, err := db.Pool.Exec(ctx, query,
		t.Name, t.Category, t.Definition, t.Enabled, t.Source,
	)
	return err
}

// ToggleToolEnabled toggles the enabled status
func (db *DB) ToggleToolEnabled(ctx context.Context, name string, enabled bool) error {
	_, err := db.Pool.Exec(ctx, "UPDATE tool_registry SET enabled = $2 WHERE name = $1", name, enabled)
	return err
}

// DeleteTool deletes a tool
func (db *DB) DeleteTool(ctx context.Context, name string) error {
	_, err := db.Pool.Exec(ctx, "DELETE FROM tool_registry WHERE name = $1", name)
	return err
}

// UpdateToolStats updates execution statistics
func (db *DB) UpdateToolStats(ctx context.Context, name string, durationMs int, success bool) error {
	query := `
		UPDATE tool_registry
		SET last_used = NOW(),
		    install_count = install_count + 1,
		    avg_exec_time = COALESCE(
		        (avg_exec_time * install_count + $2) / (install_count + 1),
		        $2
		    ),
		    success_rate = (
		        (COALESCE(success_rate, 0) * install_count + CASE WHEN $3 THEN 100.0 ELSE 0.0 END) / (install_count + 1)
		    )
		WHERE name = $1`

	_, err := db.Pool.Exec(ctx, query, name, durationMs, success)
	return err
}
