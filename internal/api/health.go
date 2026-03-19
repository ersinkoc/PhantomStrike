package api

import "net/http"

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if err := h.db.Pool.Ping(r.Context()); err != nil {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  status,
		"service": "phantomstrike",
	})
}
