package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/notify"
)

// notificationChannelResponse represents a notification channel in API responses.
type notificationChannelResponse struct {
	ID        uuid.UUID       `json:"id"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	Events    []string        `json:"events"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// notificationChannelRequest represents a request to create/update a notification channel.
type notificationChannelRequest struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Config  json.RawMessage `json:"config"`
	Events  []string        `json:"events"`
	Enabled *bool           `json:"enabled"`
}

// handleListNotificationChannels returns configured notification channels from the database.
func (h *Handler) handleListNotificationChannels(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Pool.Query(r.Context(),
		`SELECT id, type, name, config, events, enabled, created_at, updated_at
		 FROM notification_channels ORDER BY name`)
	if err != nil {
		// Fallback: return empty list
		writeJSON(w, http.StatusOK, map[string]any{"channels": []any{}})
		return
	}
	defer rows.Close()

	var channels []notificationChannelResponse
	for rows.Next() {
		var ch notificationChannelResponse
		if err := rows.Scan(&ch.ID, &ch.Type, &ch.Name, &ch.Config, &ch.Events, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
			continue
		}
		channels = append(channels, ch)
	}

	if channels == nil {
		channels = []notificationChannelResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

// handleAddNotificationChannel creates a new notification channel.
func (h *Handler) handleAddNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var req notificationChannelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}

	validTypes := map[string]bool{
		"slack": true, "discord": true, "telegram": true,
		"email": true, "webhook": true,
	}
	if !validTypes[req.Type] {
		writeError(w, http.StatusBadRequest, "invalid channel type: "+req.Type)
		return
	}

	if req.Config == nil {
		req.Config = json.RawMessage("{}")
	}
	if req.Events == nil {
		req.Events = []string{}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var id uuid.UUID
	err := h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO notification_channels (type, name, config, events, enabled)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.Type, req.Name, req.Config, req.Events, enabled,
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create notification channel")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":     id,
		"status": "created",
	})
}

// handleUpdateNotificationChannel updates an existing notification channel.
func (h *Handler) handleUpdateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid channel ID")
		return
	}

	var req notificationChannelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Build dynamic update query
	tag, err := h.db.Pool.Exec(r.Context(),
		`UPDATE notification_channels
		 SET name = COALESCE(NULLIF($1, ''), name),
		     type = COALESCE(NULLIF($2, ''), type),
		     config = COALESCE($3, config),
		     events = COALESCE($4, events),
		     enabled = COALESCE($5, enabled),
		     updated_at = NOW()
		 WHERE id = $6`,
		req.Name, req.Type, req.Config, req.Events, req.Enabled, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update notification channel")
		return
	}

	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "notification channel not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// handleDeleteNotificationChannel deletes a notification channel.
func (h *Handler) handleDeleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid channel ID")
		return
	}

	tag, err := h.db.Pool.Exec(r.Context(),
		`DELETE FROM notification_channels WHERE id = $1`, id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete notification channel")
		return
	}

	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "notification channel not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
