package notify

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDispatcher(t *testing.T) {
	d := NewDispatcher()
	require.NotNil(t, d)
	assert.NotNil(t, d.senders)
	assert.Empty(t, d.channels)
}

// mockSender records calls for testing.
type mockSender struct {
	mu     sync.Mutex
	typ    string
	events []Event
}

func newMockSender(typ string) *mockSender {
	return &mockSender{typ: typ}
}

func (m *mockSender) Type() string { return m.typ }
func (m *mockSender) Send(_ context.Context, event Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockSender) getEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Event, len(m.events))
	copy(cp, m.events)
	return cp
}

func TestDispatchToMatchingChannel(t *testing.T) {
	d := NewDispatcher()

	sender := newMockSender("console")
	d.RegisterSender(sender)
	d.RegisterChannel(ChannelConfig{
		Type:    "console",
		Name:    "test-console",
		Events:  []string{"critical_vuln"},
		Enabled: true,
	})

	event := Event{
		Type:    "critical_vuln",
		Title:   "Test Vuln",
		Message: "A critical vulnerability was found",
	}
	d.Dispatch(context.Background(), event)

	// Dispatch runs senders in goroutines; give them a moment.
	assert.Eventually(t, func() bool {
		return len(sender.getEvents()) == 1
	}, 1e9, 1e7, "expected sender to receive one event") // 1s timeout, 10ms poll

	events := sender.getEvents()
	assert.Equal(t, "critical_vuln", events[0].Type)
	assert.Equal(t, "Test Vuln", events[0].Title)
}

func TestDispatchSkipsDisabledChannel(t *testing.T) {
	d := NewDispatcher()

	sender := newMockSender("console")
	d.RegisterSender(sender)
	d.RegisterChannel(ChannelConfig{
		Type:    "console",
		Name:    "disabled-channel",
		Events:  []string{},
		Enabled: false,
	})

	d.Dispatch(context.Background(), Event{
		Type:  "mission_complete",
		Title: "Should not arrive",
	})

	// Give goroutines time (nothing should run, but we wait to be safe).
	assert.Never(t, func() bool {
		return len(sender.getEvents()) > 0
	}, 2e8, 1e7, "disabled channel should not receive events") // 200ms, 10ms
}

func TestMatchesEvents(t *testing.T) {
	tests := []struct {
		name      string
		events    []string
		eventType string
		want      bool
	}{
		{
			name:      "empty events matches all",
			events:    []string{},
			eventType: "anything",
			want:      true,
		},
		{
			name:      "nil events matches all",
			events:    nil,
			eventType: "anything",
			want:      true,
		},
		{
			name:      "specific event matches",
			events:    []string{"critical_vuln", "high_vuln"},
			eventType: "critical_vuln",
			want:      true,
		},
		{
			name:      "specific event does not match",
			events:    []string{"critical_vuln"},
			eventType: "mission_complete",
			want:      false,
		},
		{
			name:      "wildcard matches any event",
			events:    []string{"*"},
			eventType: "phase_change",
			want:      true,
		},
		{
			name:      "wildcard among others",
			events:    []string{"critical_vuln", "*"},
			eventType: "mission_failed",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesEvents(tt.events, tt.eventType)
			assert.Equal(t, tt.want, got)
		})
	}
}
