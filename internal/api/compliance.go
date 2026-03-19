package api

import (
	"net/http"

	"github.com/ersinkoc/phantomstrike/internal/compliance"
)

// handleGenerateComplianceReport generates a compliance report for a mission.
func (h *Handler) handleGenerateComplianceReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MissionID string `json:"mission_id"`
		Framework string `json:"framework"`
	}

	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.MissionID == "" {
		writeError(w, http.StatusBadRequest, "mission_id is required")
		return
	}

	if req.Framework == "" {
		writeError(w, http.StatusBadRequest, "framework is required")
		return
	}

	// Validate framework
	validFrameworks := map[string]bool{
		string(compliance.FrameworkOWASPTop10):     true,
		string(compliance.FrameworkOWASPTop102021): true,
		string(compliance.FrameworkCWE25):          true,
		string(compliance.FrameworkNISTCSF):        true,
		string(compliance.FrameworkCISControls):    true,
		string(compliance.FrameworkISO27001):       true,
		string(compliance.FrameworkGDPR):           true,
		string(compliance.FrameworkPCIDSS):         true,
		string(compliance.FrameworkHIPAA):          true,
	}
	if !validFrameworks[req.Framework] {
		writeError(w, http.StatusBadRequest, "unsupported framework")
		return
	}

	// Validate mission ID
	missionID, err := parseUUID(req.MissionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission_id")
		return
	}

	// Verify mission exists
	var exists bool
	err = h.db.Pool.QueryRow(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM missions WHERE id = $1)", missionID,
	).Scan(&exists)
	if err != nil || !exists {
		writeError(w, http.StatusNotFound, "mission not found")
		return
	}

	// Generate the compliance report
	mapper := compliance.NewMapper(h.db.Pool)
	report, err := mapper.GenerateReport(r.Context(), missionID.String(), compliance.Framework(req.Framework))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate compliance report")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"report": report})
}

// handleListFrameworks returns the list of supported compliance frameworks.
func (h *Handler) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := []map[string]string{
		{"id": string(compliance.FrameworkOWASPTop10), "name": "OWASP Top 10", "version": "2021"},
		{"id": string(compliance.FrameworkOWASPTop102021), "name": "OWASP Top 10 (2021)", "version": "2021"},
		{"id": string(compliance.FrameworkCWE25), "name": "CWE Top 25", "version": "2023"},
		{"id": string(compliance.FrameworkNISTCSF), "name": "NIST Cybersecurity Framework", "version": "1.1"},
		{"id": string(compliance.FrameworkCISControls), "name": "CIS Controls", "version": "8"},
		{"id": string(compliance.FrameworkISO27001), "name": "ISO 27001", "version": "2022"},
		{"id": string(compliance.FrameworkGDPR), "name": "GDPR", "version": "2016"},
		{"id": string(compliance.FrameworkPCIDSS), "name": "PCI DSS", "version": "4.0"},
		{"id": string(compliance.FrameworkHIPAA), "name": "HIPAA", "version": "2013"},
	}

	writeJSON(w, http.StatusOK, map[string]any{"frameworks": frameworks})
}
