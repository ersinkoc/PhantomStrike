package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Vulnerability represents a security finding
type Vulnerability struct {
	ID                 uuid.UUID       `json:"id"`
	MissionID          *uuid.UUID      `json:"mission_id"`
	ConversationID     *uuid.UUID      `json:"conversation_id"`
	ToolExecutionID    *uuid.UUID      `json:"tool_execution_id"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Severity           string          `json:"severity"`
	CVSSScore          *float64        `json:"cvss_score"`
	CVSSVector         string          `json:"cvss_vector"`
	Status             string          `json:"status"`
	Target             string          `json:"target"`
	AffectedComponent  string          `json:"affected_component"`
	Evidence           string          `json:"evidence"`
	Remediation        string          `json:"remediation"`
	CVEIDs             []string        `json:"cve_ids"`
	CWEID              string          `json:"cwe_id"`
	Tags               []string        `json:"tags"`
	FoundBy            string          `json:"found_by"`
	VerifiedBy         string          `json:"verified_by"`
	Metadata           JSONB           `json:"metadata"`
	CreatedAt          pgtype.Timestamptz `json:"created_at"`
	UpdatedAt          pgtype.Timestamptz `json:"updated_at"`
}

// CreateVulnerability creates a new vulnerability
func (db *DB) CreateVulnerability(ctx context.Context, v *Vulnerability) error {
	query := `
		INSERT INTO vulnerabilities (
			mission_id, conversation_id, tool_execution_id, title, description,
			severity, cvss_score, cvss_vector, status, target, affected_component,
			evidence, remediation, cve_ids, cwe_id, tags, found_by, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING id, created_at, updated_at`

	return db.Pool.QueryRow(ctx, query,
		v.MissionID, v.ConversationID, v.ToolExecutionID, v.Title, v.Description,
		v.Severity, v.CVSSScore, v.CVSSVector, v.Status, v.Target, v.AffectedComponent,
		v.Evidence, v.Remediation, v.CVEIDs, v.CWEID, v.Tags, v.FoundBy, v.Metadata,
	).Scan(&v.ID, &v.CreatedAt, &v.UpdatedAt)
}

// GetVulnerability retrieves a vulnerability by ID
func (db *DB) GetVulnerability(ctx context.Context, id uuid.UUID) (*Vulnerability, error) {
	query := `
		SELECT id, mission_id, conversation_id, tool_execution_id, title, description,
		       severity, cvss_score, cvss_vector, status, target, affected_component,
		       evidence, remediation, cve_ids, cwe_id, tags, found_by, verified_by,
		       metadata, created_at, updated_at
		FROM vulnerabilities WHERE id = $1`

	v := &Vulnerability{}
	err := db.Pool.QueryRow(ctx, query, id).Scan(
		&v.ID, &v.MissionID, &v.ConversationID, &v.ToolExecutionID, &v.Title, &v.Description,
		&v.Severity, &v.CVSSScore, &v.CVSSVector, &v.Status, &v.Target, &v.AffectedComponent,
		&v.Evidence, &v.Remediation, &v.CVEIDs, &v.CWEID, &v.Tags, &v.FoundBy, &v.VerifiedBy,
		&v.Metadata, &v.CreatedAt, &v.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerability: %w", err)
	}
	return v, nil
}

// ListVulnerabilities lists vulnerabilities with filtering
func (db *DB) ListVulnerabilities(ctx context.Context, missionID *uuid.UUID, severity, status string, limit, offset int) ([]*Vulnerability, int64, error) {
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if missionID != nil {
		whereClause += fmt.Sprintf(" AND mission_id = $%d", argIdx)
		args = append(args, *missionID)
		argIdx++
	}
	if severity != "" {
		whereClause += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, severity)
		argIdx++
	}
	if status != "" {
		whereClause += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM vulnerabilities " + whereClause
	var total int64
	if err := db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting vulnerabilities: %w", err)
	}

	// Query
	query := fmt.Sprintf(`
		SELECT id, mission_id, conversation_id, tool_execution_id, title, description,
		       severity, cvss_score, cvss_vector, status, target, affected_component,
		       evidence, remediation, cve_ids, cwe_id, tags, found_by, verified_by,
		       metadata, created_at, updated_at
		FROM vulnerabilities %s
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []*Vulnerability
	for rows.Next() {
		v := &Vulnerability{}
		if err := rows.Scan(
			&v.ID, &v.MissionID, &v.ConversationID, &v.ToolExecutionID, &v.Title, &v.Description,
			&v.Severity, &v.CVSSScore, &v.CVSSVector, &v.Status, &v.Target, &v.AffectedComponent,
			&v.Evidence, &v.Remediation, &v.CVEIDs, &v.CWEID, &v.Tags, &v.FoundBy, &v.VerifiedBy,
			&v.Metadata, &v.CreatedAt, &v.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning vulnerability: %w", err)
		}
		vulns = append(vulns, v)
	}

	return vulns, total, rows.Err()
}

// UpdateVulnerability updates a vulnerability
func (db *DB) UpdateVulnerability(ctx context.Context, v *Vulnerability) error {
	query := `
		UPDATE vulnerabilities
		SET title = $2, description = $3, severity = $4, cvss_score = $5,
		    cvss_vector = $6, status = $7, target = $8, affected_component = $9,
		    evidence = $10, remediation = $11, cve_ids = $12, cwe_id = $13,
		    tags = $14, verified_by = $15, metadata = $16
		WHERE id = $1`

	_, err := db.Pool.Exec(ctx, query,
		v.ID, v.Title, v.Description, v.Severity, v.CVSSScore,
		v.CVSSVector, v.Status, v.Target, v.AffectedComponent,
		v.Evidence, v.Remediation, v.CVEIDs, v.CWEID,
		v.Tags, v.VerifiedBy, v.Metadata,
	)
	return err
}

// UpdateVulnerabilityStatus updates only the status
func (db *DB) UpdateVulnerabilityStatus(ctx context.Context, id uuid.UUID, status, verifiedBy string) error {
	query := `UPDATE vulnerabilities SET status = $2, verified_by = $3 WHERE id = $1`
	_, err := db.Pool.Exec(ctx, query, id, status, verifiedBy)
	return err
}

// DeleteVulnerability deletes a vulnerability
func (db *DB) DeleteVulnerability(ctx context.Context, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, "DELETE FROM vulnerabilities WHERE id = $1", id)
	return err
}

// VulnStats holds vulnerability statistics
type VulnStats struct {
	Total      int64          `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
}

// GetVulnerabilityStats returns statistics for vulnerabilities
func (db *DB) GetVulnerabilityStats(ctx context.Context, missionID *uuid.UUID) (*VulnStats, error) {
	whereClause := ""
	args := []interface{}{}

	if missionID != nil {
		whereClause = "WHERE mission_id = $1"
		args = append(args, *missionID)
	}

	stats := &VulnStats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	// Total count
	if err := db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM vulnerabilities "+whereClause, args...,
	).Scan(&stats.Total); err != nil {
		return nil, err
	}

	// By severity
	severityQuery := fmt.Sprintf(`
		SELECT severity, COUNT(*)
		FROM vulnerabilities %s
		GROUP BY severity`, whereClause)
	rows, err := db.Pool.Query(ctx, severityQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats.BySeverity[sev] = count
	}

	// By status
	statusQuery := fmt.Sprintf(`
		SELECT status, COUNT(*)
		FROM vulnerabilities %s
		GROUP BY status`, whereClause)
	rows, err = db.Pool.Query(ctx, statusQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var count int
		if err := rows.Scan(&st, &count); err != nil {
			return nil, err
		}
		stats.ByStatus[st] = count
	}

	return stats, nil
}

// ListVulnerabilitiesByMission returns all vulnerabilities for a mission
func (db *DB) ListVulnerabilitiesByMission(ctx context.Context, missionID uuid.UUID) ([]*Vulnerability, error) {
	return db.ListVulnerabilitiesByMissionWithSeverity(ctx, missionID, "")
}

// ListVulnerabilitiesByMissionWithSeverity returns vulnerabilities for a mission filtered by severity
func (db *DB) ListVulnerabilitiesByMissionWithSeverity(ctx context.Context, missionID uuid.UUID, severity string) ([]*Vulnerability, error) {
	query := `
		SELECT id, mission_id, conversation_id, tool_execution_id, title, description,
		       severity, cvss_score, cvss_vector, status, target, affected_component,
		       evidence, remediation, cve_ids, cwe_id, tags, found_by, verified_by,
		       metadata, created_at, updated_at
		FROM vulnerabilities
		WHERE mission_id = $1`

	args := []interface{}{missionID}
	if severity != "" {
		query += ` AND severity = $2`
		args = append(args, severity)
	}

	query += `
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			created_at DESC`

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []*Vulnerability
	for rows.Next() {
		v := &Vulnerability{}
		if err := rows.Scan(
			&v.ID, &v.MissionID, &v.ConversationID, &v.ToolExecutionID, &v.Title, &v.Description,
			&v.Severity, &v.CVSSScore, &v.CVSSVector, &v.Status, &v.Target, &v.AffectedComponent,
			&v.Evidence, &v.Remediation, &v.CVEIDs, &v.CWEID, &v.Tags, &v.FoundBy, &v.VerifiedBy,
			&v.Metadata, &v.CreatedAt, &v.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning vulnerability: %w", err)
		}
		vulns = append(vulns, v)
	}

	return vulns, rows.Err()
}
