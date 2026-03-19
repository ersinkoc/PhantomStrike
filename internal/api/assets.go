package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/assets"
)

// AssetHandler handles asset-related HTTP requests.
type AssetHandler struct {
	service *assets.Service
}

// NewAssetHandler creates a new asset handler.
func NewAssetHandler(service *assets.Service) *AssetHandler {
	return &AssetHandler{service: service}
}

// RegisterRoutes registers asset routes on the mux.
func (h *AssetHandler) RegisterRoutes(mux *http.ServeMux, authMiddleware func(http.Handler) http.Handler) {
	// Asset scopes
	mux.Handle("GET /api/v1/missions/{missionID}/assets/scopes", authMiddleware(http.HandlerFunc(h.handleListScopes)))
	mux.Handle("POST /api/v1/missions/{missionID}/assets/scopes", authMiddleware(http.HandlerFunc(h.handleCreateScope)))

	// Asset discovery
	mux.Handle("POST /api/v1/missions/{missionID}/assets/discover", authMiddleware(http.HandlerFunc(h.handleStartDiscovery)))
	mux.Handle("GET /api/v1/missions/{missionID}/assets/discover/jobs", authMiddleware(http.HandlerFunc(h.handleListDiscoveryJobs)))

	// Asset listing
	mux.Handle("GET /api/v1/missions/{missionID}/assets", authMiddleware(http.HandlerFunc(h.handleListAssets)))

	// Asset changes
	mux.Handle("GET /api/v1/missions/{missionID}/assets/changes", authMiddleware(http.HandlerFunc(h.handleListAssetChanges)))

	// Asset graph
	mux.Handle("GET /api/v1/missions/{missionID}/assets/graph", authMiddleware(http.HandlerFunc(h.handleGetAssetGraph)))
}

// CreateScopeRequest represents a scope creation request.
type CreateScopeRequest struct {
	ScopeType   string `json:"scope_type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// handleCreateScope handles scope creation.
func (h *AssetHandler) handleCreateScope(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	var req CreateScopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	scope := &assets.Scope{
		MissionID:   missionID,
		ScopeType:   assets.ScopeType(req.ScopeType),
		Value:       req.Value,
		Description: req.Description,
	}

	if err := h.service.CreateScope(r.Context(), scope); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, scope)
}

// handleListScopes handles scope listing.
func (h *AssetHandler) handleListScopes(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	scopes, err := h.service.GetScopes(r.Context(), missionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, scopes)
}

// handleListAssets handles asset listing.
func (h *AssetHandler) handleListAssets(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// Get all assets for the mission
	// In production, would support filtering by type, status, etc.
	scopes, err := h.service.GetScopes(r.Context(), missionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build response with scopes and their assets
	response := map[string]interface{}{
		"mission_id": missionID,
		"scopes":     scopes,
	}

	writeJSON(w, http.StatusOK, response)
}

// StartDiscoveryRequest represents a discovery job start request.
type StartDiscoveryRequest struct {
	JobType string             `json:"job_type"`
	ScopeID string             `json:"scope_id,omitempty"`
	Config  assets.ScanConfig  `json:"config,omitempty"`
}

// handleStartDiscovery handles discovery job creation and start.
func (h *AssetHandler) handleStartDiscovery(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	var req StartDiscoveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	job := &assets.DiscoveryJob{
		MissionID: missionID,
		JobType:   assets.JobType(req.JobType),
		Config:    req.Config,
	}

	if req.ScopeID != "" {
		scopeID, err := uuid.Parse(req.ScopeID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid scope ID")
			return
		}
		job.ScopeID = &scopeID
	}

	if err := h.service.CreateDiscoveryJob(r.Context(), job); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Start the job asynchronously
	if err := h.service.StartDiscoveryJob(r.Context(), job.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID,
		"status": "started",
	})
}

// handleListDiscoveryJobs handles discovery job listing.
func (h *AssetHandler) handleListDiscoveryJobs(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// In production, would query from database
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mission_id": missionID,
		"jobs":       []assets.DiscoveryJob{},
	})
}

// handleListAssetChanges handles asset change listing.
func (h *AssetHandler) handleListAssetChanges(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// In production, would query asset_changes table
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mission_id": missionID,
		"changes":    []interface{}{},
	})
}

// handleGetAssetGraph handles asset graph retrieval.
func (h *AssetHandler) handleGetAssetGraph(w http.ResponseWriter, r *http.Request) {
	missionID, err := parseUUID(r.PathValue("missionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid mission ID")
		return
	}

	// In production, would build graph from asset relationships
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mission_id": missionID,
		"nodes":      []interface{}{},
		"edges":      []interface{}{},
	})
}
