package api

import (
	"net/http"

	"github.com/ersinkoc/phantomstrike/internal/notify"
)

// handleListNotificationChannels returns configured notification channels from config.
func (h *Handler) handleListNotificationChannels(w http.ResponseWriter, r *http.Request) {
	// Query notification channels from DB if available
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, name, type, enabled, config, filters, severity FROM notification_channels ORDER BY name`)
	if err != nil {
		// Fallback: return empty list
		writeJSON(w, http.StatusOK, map[string]any{"channels": []any{}})
		return
	}
	defer rows.Close()

	var channels []map[string]any
	for rows.Next() {
		var ch notify.Channel
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Enabled, &ch.Config, &ch.Filters, &ch.Severity); err != nil {
			continue
		}
		channels = append(channels, map[string]any{
			"id":       ch.ID,
			"name":     ch.Name,
			"type":     ch.Type,
			"enabled":  ch.Enabled,
			"filters":  ch.Filters,
			"severity": ch.Severity,
		})
	}

	if channels == nil {
		channels = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

// handleTestNotificationChannel sends a test notification through the specified channel type.
func (h *Handler) handleTestNotificationChannel(w http.ResponseWriter, r *http.Request) {
	channelType := r.PathValue("type")
	if channelType == "" {
		writeError(w, http.StatusBadRequest, "channel type is required")
		return
	}

	// Query the channel configuration from DB
	var ch notify.Channel
	err := h.db.Pool.QueryRow(r.Context(),
		`SELECT id, name, type, enabled, config, filters, severity FROM notification_channels WHERE type = $1 AND enabled = true LIMIT 1`,
		channelType,
	).Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Enabled, &ch.Config, &ch.Filters, &ch.Severity)
	if err != nil {
		writeError(w, http.StatusNotFound, "no enabled channel found for type: "+channelType)
		return
	}

	// Create a test notification event
	hub := notify.NewHub(h.db.Pool)
	testNotif := &notify.Notification{
		Type:     "test",
		Title:    "PhantomStrike Test Notification",
		Message:  "This is a test notification from PhantomStrike to verify your channel configuration.",
		Severity: "info",
	}

	if err := hub.Send(r.Context(), testNotif); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to send test notification: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "sent",
		"channel": channelType,
	})
}
