package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/agent"
	"github.com/ersinkoc/phantomstrike/internal/auth"
	"github.com/ersinkoc/phantomstrike/internal/cache"
	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/storage"
	"github.com/ersinkoc/phantomstrike/internal/store"
	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// Handler is the main API handler that registers all routes.
type Handler struct {
	cfg      *config.Config
	db       *store.DB
	authSvc  *auth.Service
	swarm    *agent.Swarm
	hub      *WSHub
	registry *tool.Registry
	cache    *cache.Cache
	storage  storage.Provider
}

// NewHandler creates a new API handler.
func NewHandler(cfg *config.Config, db *store.DB, authSvc *auth.Service, swarm *agent.Swarm, hub *WSHub, registry *tool.Registry) *Handler {
	return &Handler{
		cfg:      cfg,
		db:       db,
		authSvc:  authSvc,
		swarm:    swarm,
		hub:      hub,
		registry: registry,
	}
}

// SetCache sets the Redis cache on the handler.
func (h *Handler) SetCache(c *cache.Cache) { h.cache = c }

// SetStorage sets the storage provider on the handler.
func (h *Handler) SetStorage(s storage.Provider) { h.storage = s }

// RegisterRoutes registers all API routes on the mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Health check (public)
	mux.HandleFunc("GET /health", h.handleHealth)

	// Auth routes (public)
	mux.HandleFunc("POST /api/v1/auth/login", h.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/register", h.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/refresh", h.handleRefresh)

	// Protected routes
	protected := h.authSvc.Middleware

	// Auth - authenticated
	mux.Handle("GET /api/v1/auth/me", protected(http.HandlerFunc(h.handleMe)))
	mux.Handle("PUT /api/v1/auth/me", protected(http.HandlerFunc(h.handleUpdateMe)))
	mux.Handle("POST /api/v1/auth/logout", protected(http.HandlerFunc(h.handleLogout)))

	// Missions
	mux.Handle("GET /api/v1/missions", protected(http.HandlerFunc(h.handleListMissions)))
	mux.Handle("POST /api/v1/missions", protected(http.HandlerFunc(h.handleCreateMission)))
	mux.Handle("GET /api/v1/missions/{id}", protected(http.HandlerFunc(h.handleGetMission)))
	mux.Handle("PUT /api/v1/missions/{id}", protected(http.HandlerFunc(h.handleUpdateMission)))
	mux.Handle("DELETE /api/v1/missions/{id}", protected(http.HandlerFunc(h.handleDeleteMission)))
	mux.Handle("POST /api/v1/missions/{id}/start", protected(http.HandlerFunc(h.handleStartMission)))
	mux.Handle("POST /api/v1/missions/{id}/pause", protected(http.HandlerFunc(h.handlePauseMission)))
	mux.Handle("POST /api/v1/missions/{id}/cancel", protected(http.HandlerFunc(h.handleCancelMission)))
	mux.Handle("GET /api/v1/missions/{id}/chain", protected(http.HandlerFunc(h.handleGetAttackChain)))
	mux.Handle("GET /api/v1/missions/{id}/vulns", protected(http.HandlerFunc(h.handleGetMissionVulns)))
	mux.Handle("GET /api/v1/missions/{id}/tools", protected(http.HandlerFunc(h.handleGetMissionTools)))
	mux.Handle("GET /api/v1/missions/{id}/reports", protected(http.HandlerFunc(h.handleGetMissionReports)))

	// Conversations
	mux.Handle("GET /api/v1/missions/{id}/conversations", protected(http.HandlerFunc(h.handleListConversations)))
	mux.Handle("GET /api/v1/conversations/{id}/messages", protected(http.HandlerFunc(h.handleGetMessages)))
	mux.Handle("POST /api/v1/conversations/{id}/messages", protected(http.HandlerFunc(h.handleSendMessage)))

	// Vulnerabilities
	mux.Handle("GET /api/v1/vulnerabilities", protected(http.HandlerFunc(h.handleListVulns)))
	mux.Handle("POST /api/v1/vulnerabilities", protected(http.HandlerFunc(h.handleCreateVuln)))
	mux.Handle("GET /api/v1/vulnerabilities/{id}", protected(http.HandlerFunc(h.handleGetVuln)))
	mux.Handle("PUT /api/v1/vulnerabilities/{id}", protected(http.HandlerFunc(h.handleUpdateVuln)))
	mux.Handle("DELETE /api/v1/vulnerabilities/{id}", protected(http.HandlerFunc(h.handleDeleteVuln)))
	mux.Handle("GET /api/v1/vulnerabilities/stats", protected(http.HandlerFunc(h.handleVulnStats)))

	// Tools
	mux.Handle("GET /api/v1/tools", protected(http.HandlerFunc(h.handleListTools)))
	mux.Handle("GET /api/v1/tools/{name}", protected(http.HandlerFunc(h.handleGetTool)))
	mux.Handle("PUT /api/v1/tools/{name}/toggle", protected(http.HandlerFunc(h.handleToggleTool)))
	mux.Handle("GET /api/v1/tools/categories", protected(http.HandlerFunc(h.handleToolCategories)))

	// Settings
	mux.Handle("GET /api/v1/settings", protected(http.HandlerFunc(h.handleGetSettings)))
	mux.Handle("PUT /api/v1/settings", protected(http.HandlerFunc(h.handleUpdateSettings)))

	// Knowledge
	mux.Handle("GET /api/v1/knowledge", protected(http.HandlerFunc(h.handleKnowledgeList)))
	mux.Handle("POST /api/v1/knowledge/search", protected(http.HandlerFunc(h.handleKnowledgeSearch)))
	mux.Handle("GET /api/v1/knowledge/categories", protected(http.HandlerFunc(h.handleKnowledgeCategories)))

	// Reports
	mux.Handle("GET /api/v1/reports", protected(http.HandlerFunc(h.handleListReports)))
	mux.Handle("POST /api/v1/reports", protected(http.HandlerFunc(h.handleCreateReport)))
	mux.Handle("GET /api/v1/reports/{id}/download", protected(http.HandlerFunc(h.handleDownloadReport)))

	// Scheduler
	mux.Handle("GET /api/v1/scheduler", protected(http.HandlerFunc(h.handleListScheduler)))
	mux.Handle("POST /api/v1/scheduler", protected(http.HandlerFunc(h.handleCreateScheduler)))
	mux.Handle("PUT /api/v1/scheduler/{id}", protected(http.HandlerFunc(h.handleUpdateScheduler)))
	mux.Handle("POST /api/v1/scheduler/{id}/trigger", protected(http.HandlerFunc(h.handleTriggerScheduler)))
	mux.Handle("DELETE /api/v1/scheduler/{id}", protected(http.HandlerFunc(h.handleDeleteScheduler)))

	// Roles & Skills
	mux.Handle("GET /api/v1/roles", protected(http.HandlerFunc(h.handleListRoles)))
	mux.Handle("GET /api/v1/skills", protected(http.HandlerFunc(h.handleListSkills)))

	// Marketplace
	mux.Handle("GET /api/v1/marketplace/tools", protected(http.HandlerFunc(h.handleListMarketplaceTools)))
	mux.Handle("GET /api/v1/marketplace/skills", protected(http.HandlerFunc(h.handleListMarketplaceSkills)))
}

// --- Response helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
