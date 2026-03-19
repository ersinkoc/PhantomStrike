package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type vulnRequest struct {
	MissionID         *uuid.UUID `json:"mission_id"`
	Title             string     `json:"title"`
	Description       string     `json:"description"`
	Severity          string     `json:"severity"`
	CVSSScore         *float64   `json:"cvss_score"`
	CVSSVector        string     `json:"cvss_vector"`
	Status            string     `json:"status"`
	Target            string     `json:"target"`
	AffectedComponent string    `json:"affected_component"`
	Evidence          string     `json:"evidence"`
	Remediation       string     `json:"remediation"`
	CVEIDs            []string   `json:"cve_ids"`
	CWEID             string     `json:"cwe_id"`
	Tags              []string   `json:"tags"`
	FoundBy           string     `json:"found_by"`
}

func (h *Handler) handleListVulns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")

	query := `SELECT id, mission_id, title, severity, cvss_score, status, target, found_by, created_at FROM vulnerabilities WHERE 1=1`
	args := []any{}
	argIdx := 1

	if severity != "" {
		query += ` AND severity = $` + strconv.Itoa(argIdx)
		args = append(args, severity)
		argIdx++
	}
	if status != "" {
		query += ` AND status = $` + strconv.Itoa(argIdx)
		args = append(args, status)
		argIdx++
	}

	query += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var vulns []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var missionID *uuid.UUID
		var title, severity, status string
		var cvssScore *float64
		var target, foundBy *string
		var createdAt time.Time
		if err := rows.Scan(&id, &missionID, &title, &severity, &cvssScore, &status, &target, &foundBy, &createdAt); err != nil {
			continue
		}
		vulns = append(vulns, map[string]any{
			"id": id, "mission_id": missionID, "title": title, "severity": severity,
			"cvss_score": cvssScore, "status": status, "target": target, "found_by": foundBy, "created_at": createdAt,
		})
	}

	if vulns == nil {
		vulns = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns})
}

func (h *Handler) handleCreateVuln(w http.ResponseWriter, r *http.Request) {
	var req vulnRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Title == "" || req.Severity == "" {
		writeError(w, http.StatusBadRequest, "title and severity are required")
		return
	}

	var id uuid.UUID
	err := h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO vulnerabilities (mission_id, title, description, severity, cvss_score, cvss_vector, status, target, affected_component, evidence, remediation, cve_ids, cwe_id, tags, found_by)
		 VALUES ($1, $2, $3, $4, $5, $6, COALESCE(NULLIF($7,''), 'open'), $8, $9, $10, $11, $12, $13, $14, $15)
		 RETURNING id`,
		req.MissionID, req.Title, req.Description, req.Severity, req.CVSSScore, req.CVSSVector,
		req.Status, req.Target, req.AffectedComponent, req.Evidence, req.Remediation,
		req.CVEIDs, req.CWEID, req.Tags, req.FoundBy,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create vulnerability")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *Handler) handleGetVuln(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid vulnerability ID")
		return
	}

	var v map[string]any
	var vID uuid.UUID
	var title, description, severity, status string
	var cvssScore *float64
	var cvssVector, target, component, evidence, remediation, cweID, foundBy, verifiedBy *string
	var cveIDs, tags []string
	var createdAt, updatedAt time.Time

	err = h.db.Pool.QueryRow(r.Context(),
		`SELECT id, title, description, severity, cvss_score, cvss_vector, status, target, affected_component, evidence, remediation, cve_ids, cwe_id, tags, found_by, verified_by, created_at, updated_at
		 FROM vulnerabilities WHERE id = $1`, id,
	).Scan(&vID, &title, &description, &severity, &cvssScore, &cvssVector, &status, &target, &component, &evidence, &remediation, &cveIDs, &cweID, &tags, &foundBy, &verifiedBy, &createdAt, &updatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "vulnerability not found")
		return
	}

	v = map[string]any{
		"id": vID, "title": title, "description": description, "severity": severity,
		"cvss_score": cvssScore, "cvss_vector": cvssVector, "status": status,
		"target": target, "affected_component": component, "evidence": evidence,
		"remediation": remediation, "cve_ids": cveIDs, "cwe_id": cweID, "tags": tags,
		"found_by": foundBy, "verified_by": verifiedBy,
		"created_at": createdAt, "updated_at": updatedAt,
	}

	writeJSON(w, http.StatusOK, v)
}

func (h *Handler) handleUpdateVuln(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid vulnerability ID")
		return
	}

	var req vulnRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	_, err = h.db.Pool.Exec(r.Context(),
		`UPDATE vulnerabilities SET
			title = COALESCE(NULLIF($1,''), title),
			description = COALESCE(NULLIF($2,''), description),
			severity = COALESCE(NULLIF($3,''), severity),
			status = COALESCE(NULLIF($4,''), status),
			remediation = COALESCE(NULLIF($5,''), remediation),
			updated_at = NOW()
		 WHERE id = $6`,
		req.Title, req.Description, req.Severity, req.Status, req.Remediation, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) handleDeleteVuln(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid vulnerability ID")
		return
	}

	_, _ = h.db.Pool.Exec(r.Context(), "DELETE FROM vulnerabilities WHERE id = $1", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) handleVulnStats(w http.ResponseWriter, r *http.Request) {
	// Check cache first
	if h.cache != nil {
		var cached map[string]any
		if err := h.cache.GetJSON(r.Context(), "api:vulns:stats", &cached); err == nil {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

	var total, critical, high, medium, low, info int
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM vulnerabilities").Scan(&total)
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'").Scan(&critical)
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high'").Scan(&high)
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium'").Scan(&medium)
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low'").Scan(&low)
	_ = h.db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'info'").Scan(&info)

	result := map[string]any{
		"total":    total,
		"critical": critical,
		"high":     high,
		"medium":   medium,
		"low":      low,
		"info":     info,
	}

	// Cache the result
	if h.cache != nil {
		_ = h.cache.SetJSON(r.Context(), "api:vulns:stats", result, 60*time.Second)
	}

	writeJSON(w, http.StatusOK, result)
}
