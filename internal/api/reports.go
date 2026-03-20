package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/report"
	"github.com/ersinkoc/phantomstrike/internal/storage"
	"github.com/google/uuid"
)

// handleListReports returns generated reports
func (h *Handler) handleListReports(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT r.id, r.mission_id, r.format, r.title, r.status, r.file_path, r.file_size, r.created_at,
			 m.name as mission_name
		 FROM reports r
		 LEFT JOIN missions m ON r.mission_id = m.id
		 ORDER BY r.created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	var reports []map[string]interface{}
	for rows.Next() {
		var id, format, title, status string
		var missionID, missionName, filePath interface{}
		var fileSize int64
		var createdAt string
		if err := rows.Scan(&id, &missionID, &format, &title, &status, &filePath, &fileSize, &createdAt, &missionName); err != nil {
			continue
		}
		reports = append(reports, map[string]interface{}{
			"id":           id,
			"mission_id":   missionID,
			"mission_name": missionName,
			"format":       format,
			"title":        title,
			"status":       status,
			"file_path":    filePath,
			"file_size":    fileSize,
			"created_at":   createdAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"reports": reports})
}

// handleCreateReport creates a new report generation job
func (h *Handler) handleCreateReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MissionID string `json:"mission_id"`
		Format    string `json:"format"`
		Title     string `json:"title"`
	}

	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	missionID, err := parseUUID(req.MissionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// Validate format
	format := req.Format
	if format == "" {
		format = "json"
	}
	validFormats := map[string]bool{"json": true, "md": true, "markdown": true, "html": true, "pdf": true}
	if !validFormats[format] {
		writeError(w, http.StatusBadRequest, "invalid format: must be json, md, markdown, html, or pdf")
		return
	}

	// Get mission name
	var missionName, missionDesc string
	var targetData map[string]any
	err = h.db.Pool.QueryRow(r.Context(),
		"SELECT name, description, target FROM missions WHERE id = $1",
		missionID,
	).Scan(&missionName, &missionDesc, &targetData)
	if err != nil {
		writeError(w, http.StatusNotFound, "mission not found")
		return
	}

	// Generate title if not provided
	title := req.Title
	if title == "" {
		title = "Security Assessment Report - " + missionName
	}

	// Create report record
	reportID := uuid.New()
	_, err = h.db.Pool.Exec(r.Context(),
		`INSERT INTO reports (id, mission_id, format, title, status, file_path, file_size, created_at)
		 VALUES ($1, $2, $3, $4, 'generating', NULL, 0, NOW())`,
		reportID, missionID, format, title,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create report record")
		return
	}

	// Generate report synchronously for now (could be async)
	reportData, err := h.generateReport(r.Context(), missionID, missionName, missionDesc, targetData)
	if err != nil {
		h.db.Pool.Exec(r.Context(),
			"UPDATE reports SET status = 'failed' WHERE id = $1",
			reportID)
		writeError(w, http.StatusInternalServerError, "report generation failed")
		return
	}

	// Store the report file
	storageProvider, err := storage.NewLocalStorage("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage initialization failed")
		return
	}

	filePath := storage.GeneratePath("reports", reportID.String(), format)
	_, err = storageProvider.Save(r.Context(), filePath, reportData)
	if err != nil {
		h.db.Pool.Exec(r.Context(),
			"UPDATE reports SET status = 'failed' WHERE id = $1",
			reportID)
		writeError(w, http.StatusInternalServerError, "failed to save report")
		return
	}

	// Update report record
	_, err = h.db.Pool.Exec(r.Context(),
		"UPDATE reports SET status = 'ready', file_path = $1, file_size = $2 WHERE id = $3",
		filePath, len(reportData), reportID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update report")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":        reportID,
		"mission_id": missionID,
		"format":    format,
		"title":     title,
		"status":    "ready",
		"file_path": filePath,
		"file_size": len(reportData),
	})
}

// handleDownloadReport serves report files
func (h *Handler) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "report ID required")
		return
	}

	reportID, err := parseUUID(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid report ID")
		return
	}

	var filePath, format, title, status string
	err = h.db.Pool.QueryRow(r.Context(),
		"SELECT file_path, format, title, status FROM reports WHERE id = $1", reportID,
	).Scan(&filePath, &format, &title, &status)
	if err != nil {
		writeError(w, http.StatusNotFound, "report not found")
		return
	}

	if status != "ready" {
		writeError(w, http.StatusBadRequest, "report is not ready yet")
		return
	}

	if filePath == "" {
		writeError(w, http.StatusNotFound, "report file not found")
		return
	}

	// Load and serve the file
	storageProvider, err := storage.NewLocalStorage("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage error")
		return
	}

	data, err := storageProvider.Load(r.Context(), filePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "report file not found")
		return
	}

	// Set appropriate headers
	contentType := storage.GetMimeType(filePath)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Set filename for download
	filename := title
	if filename == "" {
		filename = "report"
	}
	filename = filename + "." + format
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// generateReport creates the report content
func (h *Handler) generateReport(ctx context.Context, missionID uuid.UUID, missionName, missionDesc string, target map[string]any) ([]byte, error) {
	// Get mission timeline
	var startTime, endTime *time.Time
	h.db.Pool.QueryRow(ctx,
		"SELECT started_at, completed_at FROM missions WHERE id = $1", missionID,
	).Scan(&startTime, &endTime)

	// Get vulnerabilities
	rows, err := h.db.Pool.Query(ctx,
		`SELECT id, title, description, severity, cvss_score, cvss_vector, target,
			affected_component, evidence, remediation, cve_ids, cwe_id, found_by, created_at
		 FROM vulnerabilities WHERE mission_id = $1 ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END, cvss_score DESC NULLS LAST`,
		missionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []report.Vulnerability
	bySeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	for rows.Next() {
		var v report.Vulnerability
		var cveIDs []string
		var createdAt time.Time
		err := rows.Scan(&v.ID, &v.Title, &v.Description, &v.Severity, &v.CVSSScore, &v.CVSSVector,
			&v.Target, &v.AffectedComponent, &v.Evidence, &v.Remediation, &cveIDs, &v.CWEID, &v.FoundBy, &createdAt)
		if err != nil {
			continue
		}
		v.CVEIDs = cveIDs
		v.CreatedAt = createdAt.Format(time.RFC3339)
		vulns = append(vulns, v)
		bySeverity[v.Severity]++
	}

	// Get attack chain nodes
	chainRows, err := h.db.Pool.Query(ctx,
		`SELECT id, node_type, label, severity, phase FROM attack_chain_nodes WHERE mission_id = $1`,
		missionID)
	if err != nil {
		chainRows = nil
	}
	defer chainRows.Close()

	var chain []report.ChainNode
	if chainRows != nil {
		for chainRows.Next() {
			var n report.ChainNode
			if err := chainRows.Scan(&n.ID, &n.Type, &n.Label, &n.Severity, &n.Phase); err == nil {
				chain = append(chain, n)
			}
		}
	}

	// Prepare report data
	data := &report.Data{
		MissionID:       missionID,
		MissionName:     missionName,
		MissionDesc:     missionDesc,
		Target:          target,
		StartTime:       startTime,
		EndTime:         endTime,
		Vulnerabilities: vulns,
		Summary: report.Summary{
			Total:      len(vulns),
			BySeverity: bySeverity,
		},
		AttackChain: chain,
	}

	// Generate report (default to markdown)
	gen := report.NewGenerator(missionID, missionName)
	return gen.GenerateMarkdown(data), nil
}
