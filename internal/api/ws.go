package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/websocket"
)

// WSHub manages WebSocket connections for real-time streaming.
type WSHub struct {
	mu          sync.RWMutex
	connections map[uuid.UUID]map[*websocket.Conn]bool // missionID -> connections
}

// NewWSHub creates a new WebSocket hub.
func NewWSHub() *WSHub {
	return &WSHub{
		connections: make(map[uuid.UUID]map[*websocket.Conn]bool),
	}
}

// Subscribe adds a connection to a mission's broadcast group.
func (hub *WSHub) Subscribe(missionID uuid.UUID, conn *websocket.Conn) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if hub.connections[missionID] == nil {
		hub.connections[missionID] = make(map[*websocket.Conn]bool)
	}
	hub.connections[missionID][conn] = true
}

// Unsubscribe removes a connection from a mission's broadcast group.
func (hub *WSHub) Unsubscribe(missionID uuid.UUID, conn *websocket.Conn) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if conns, ok := hub.connections[missionID]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(hub.connections, missionID)
		}
	}
}

// Broadcast sends a message to all connections subscribed to a mission.
func (hub *WSHub) Broadcast(missionID uuid.UUID, event WSEvent) {
	hub.mu.RLock()
	conns := hub.connections[missionID]
	hub.mu.RUnlock()

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	for conn := range conns {
		if _, err := conn.Write(data); err != nil {
			slog.Debug("failed to write to websocket", "error", err)
			hub.Unsubscribe(missionID, conn)
			conn.Close()
		}
	}
}

// WSEvent represents a WebSocket event message.
type WSEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// WSMessage represents an incoming WebSocket message from client.
type WSMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// HandleWebSocket handles WebSocket connections for real-time streaming.
func (h *Handler) HandleWebSocket(hub *WSHub) http.Handler {
	return websocket.Handler(func(conn *websocket.Conn) {
		defer conn.Close()

		// Authenticate via query param
		token := conn.Request().URL.Query().Get("token")
		if token == "" {
			websocket.JSON.Send(conn, WSEvent{Type: "error", Data: "missing token"})
			return
		}

		claims, err := h.authSvc.ValidateToken(token)
		if err != nil {
			websocket.JSON.Send(conn, WSEvent{Type: "error", Data: "invalid token"})
			return
		}

		slog.Info("websocket connected", "user", claims.Email)

		// Send connected event
		websocket.JSON.Send(conn, WSEvent{Type: "connected", Data: map[string]any{
			"user_id": claims.UserID,
		}})

		ctx, cancel := context.WithCancel(conn.Request().Context())
		defer cancel()

		// Read messages from client
		for {
			var msg WSMessage
			if err := websocket.JSON.Receive(conn, &msg); err != nil {
				slog.Debug("websocket read error", "error", err)
				break
			}

			switch msg.Type {
			case "subscribe":
				var data struct {
					MissionID uuid.UUID `json:"mission_id"`
				}
				if err := json.Unmarshal(msg.Data, &data); err == nil {
					hub.Subscribe(data.MissionID, conn)
					websocket.JSON.Send(conn, WSEvent{Type: "subscribed", Data: data.MissionID})
				}

			case "unsubscribe":
				var data struct {
					MissionID uuid.UUID `json:"mission_id"`
				}
				if err := json.Unmarshal(msg.Data, &data); err == nil {
					hub.Unsubscribe(data.MissionID, conn)
				}

			case "ping":
				websocket.JSON.Send(conn, WSEvent{Type: "pong", Data: time.Now().Unix()})
			}

			_ = ctx // keep ctx alive
		}
	})
}
