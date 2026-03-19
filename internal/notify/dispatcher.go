package notify

import (
	"context"
	"fmt"
	"log/slog"
)

// Channel represents a notification channel configuration.
type Channel struct {
	Type    string         `json:"type"` // slack, discord, telegram, email, webhook
	Name    string         `json:"name"`
	Config  map[string]any `json:"config"`
	Events  []string       `json:"events"`
	Enabled bool           `json:"enabled"`
}

// Event represents a notification event.
type Event struct {
	Type      string `json:"type"` // critical_vuln, high_vuln, mission_complete, mission_failed, phase_change
	MissionID string `json:"mission_id,omitempty"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Severity  string `json:"severity,omitempty"`
}

// Sender is the interface for notification channel implementations.
type Sender interface {
	Send(ctx context.Context, event Event) error
	Type() string
}

// Dispatcher manages notification channels and routes events.
type Dispatcher struct {
	channels []Channel
	senders  map[string]Sender
}

// NewDispatcher creates a new notification dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		senders: make(map[string]Sender),
	}
}

// RegisterChannel adds a notification channel.
func (d *Dispatcher) RegisterChannel(ch Channel) {
	d.channels = append(d.channels, ch)
	slog.Info("registered notification channel", "type", ch.Type, "name", ch.Name)
}

// Dispatch sends a notification event to all matching channels.
func (d *Dispatcher) Dispatch(ctx context.Context, event Event) {
	for _, ch := range d.channels {
		if !ch.Enabled {
			continue
		}
		if !matchesEvents(ch.Events, event.Type) {
			continue
		}

		sender, ok := d.senders[ch.Type]
		if !ok {
			slog.Warn("no sender for channel type", "type", ch.Type)
			continue
		}

		go func(s Sender, e Event) {
			if err := s.Send(ctx, e); err != nil {
				slog.Error("notification send failed",
					"channel", s.Type(),
					"event", e.Type,
					"error", err,
				)
			}
		}(sender, event)
	}
}

// RegisterSender registers a notification sender implementation.
func (d *Dispatcher) RegisterSender(s Sender) {
	d.senders[s.Type()] = s
}

func matchesEvents(events []string, eventType string) bool {
	if len(events) == 0 {
		return true // No filter = all events
	}
	for _, e := range events {
		if e == eventType || e == "*" {
			return true
		}
	}
	return false
}

// WebhookSender sends notifications via HTTP webhook.
type WebhookSender struct {
	url string
}

// NewWebhookSender creates a new webhook sender.
func NewWebhookSender(url string) *WebhookSender {
	return &WebhookSender{url: url}
}

func (w *WebhookSender) Type() string { return "webhook" }
func (w *WebhookSender) Send(ctx context.Context, event Event) error {
	// TODO: Implement HTTP POST to webhook URL
	_ = fmt.Sprintf("POST %s: %s", w.url, event.Title)
	return nil
}
