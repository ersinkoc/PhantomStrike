package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Mission represents a penetration testing engagement
type Mission struct {
	ID           uuid.UUID       `json:"id"`
	OrgID        *uuid.UUID      `json:"org_id"`
	CreatedBy    *uuid.UUID      `json:"created_by"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Status       string          `json:"status"`
	Mode         string          `json:"mode"`
	Depth        string          `json:"depth"`
	Target       JSONB           `json:"target"`
	Config       JSONB           `json:"config"`
	Phases       []string        `json:"phases"`
	CurrentPhase string          `json:"current_phase"`
	Progress     int             `json:"progress"`
	StartedAt    *pgtype.Timestamptz `json:"started_at"`
	CompletedAt  *pgtype.Timestamptz `json:"completed_at"`
	CreatedAt    pgtype.Timestamptz  `json:"created_at"`
	UpdatedAt    pgtype.Timestamptz  `json:"updated_at"`
}

// CreateMission creates a new mission
func (db *DB) CreateMission(ctx context.Context, m *Mission) error {
	query := `
		INSERT INTO missions (org_id, created_by, name, description, status, mode, depth, target, config, phases, current_phase, progress)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at`

	return db.Pool.QueryRow(ctx, query,
		m.OrgID, m.CreatedBy, m.Name, m.Description, m.Status, m.Mode, m.Depth,
		m.Target, m.Config, m.Phases, m.CurrentPhase, m.Progress,
	).Scan(&m.ID, &m.CreatedAt, &m.UpdatedAt)
}

// GetMission retrieves a mission by ID
func (db *DB) GetMission(ctx context.Context, id uuid.UUID) (*Mission, error) {
	query := `
		SELECT id, org_id, created_by, name, description, status, mode, depth,
		       target, config, phases, current_phase, progress,
		       started_at, completed_at, created_at, updated_at
		FROM missions WHERE id = $1`

	m := &Mission{}
	err := db.Pool.QueryRow(ctx, query, id).Scan(
		&m.ID, &m.OrgID, &m.CreatedBy, &m.Name, &m.Description,
		&m.Status, &m.Mode, &m.Depth, &m.Target, &m.Config,
		&m.Phases, &m.CurrentPhase, &m.Progress,
		&m.StartedAt, &m.CompletedAt, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying mission: %w", err)
	}
	return m, nil
}

// ListMissions lists missions with optional filtering
func (db *DB) ListMissions(ctx context.Context, orgID *uuid.UUID, status string, limit, offset int) ([]*Mission, int64, error) {
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if orgID != nil {
		whereClause += fmt.Sprintf(" AND org_id = $%d", argIdx)
		args = append(args, *orgID)
		argIdx++
	}
	if status != "" {
		whereClause += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	// Count query
	countQuery := "SELECT COUNT(*) FROM missions " + whereClause
	var total int64
	if err := db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting missions: %w", err)
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT id, org_id, created_by, name, description, status, mode, depth,
		       target, config, phases, current_phase, progress,
		       started_at, completed_at, created_at, updated_at
		FROM missions %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying missions: %w", err)
	}
	defer rows.Close()

	var missions []*Mission
	for rows.Next() {
		m := &Mission{}
		if err := rows.Scan(
			&m.ID, &m.OrgID, &m.CreatedBy, &m.Name, &m.Description,
			&m.Status, &m.Mode, &m.Depth, &m.Target, &m.Config,
			&m.Phases, &m.CurrentPhase, &m.Progress,
			&m.StartedAt, &m.CompletedAt, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning mission: %w", err)
		}
		missions = append(missions, m)
	}

	return missions, total, rows.Err()
}

// UpdateMission updates a mission
func (db *DB) UpdateMission(ctx context.Context, m *Mission) error {
	query := `
		UPDATE missions
		SET name = $2, description = $3, status = $4, mode = $5, depth = $6,
		    target = $7, config = $8, phases = $9, current_phase = $10, progress = $11
		WHERE id = $1`

	_, err := db.Pool.Exec(ctx, query,
		m.ID, m.Name, m.Description, m.Status, m.Mode, m.Depth,
		m.Target, m.Config, m.Phases, m.CurrentPhase, m.Progress,
	)
	return err
}

// DeleteMission deletes a mission
func (db *DB) DeleteMission(ctx context.Context, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, "DELETE FROM missions WHERE id = $1", id)
	return err
}

// UpdateMissionStatus updates mission status and timestamps
func (db *DB) UpdateMissionStatus(ctx context.Context, id uuid.UUID, status string) error {
	var query string
	switch status {
	case "running", "recon", "scanning", "exploitation", "post_exploit", "reporting":
		query = `UPDATE missions SET status = $2, started_at = COALESCE(started_at, NOW()) WHERE id = $1`
	case "completed", "failed", "cancelled":
		query = `UPDATE missions SET status = $2, completed_at = NOW() WHERE id = $1`
	case "paused":
		query = `UPDATE missions SET status = $2 WHERE id = $1`
	default:
		query = `UPDATE missions SET status = $2 WHERE id = $1`
	}
	_, err := db.Pool.Exec(ctx, query, id, status)
	return err
}

// UpdateMissionPhase updates the current phase
func (db *DB) UpdateMissionPhase(ctx context.Context, id uuid.UUID, phase string, progress int) error {
	query := `UPDATE missions SET current_phase = $2, progress = $3 WHERE id = $1`
	_, err := db.Pool.Exec(ctx, query, id, phase, progress)
	return err
}

// JSONB is a wrapper for PostgreSQL JSONB
type JSONB map[string]interface{}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, j)
	case string:
		return json.Unmarshal([]byte(v), j)
	default:
		return fmt.Errorf("cannot scan type %T into JSONB", value)
	}
}

func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}
