package agent

import (
	"sync"

	"github.com/ersinkoc/phantomstrike/internal/provider"
)

// Memory manages the working memory for an agent within a conversation.
type Memory struct {
	mu       sync.RWMutex
	messages []provider.Message
	findings []Finding
	maxMsgs  int
}

// Finding represents a security finding discovered during execution.
type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Tool        string `json:"tool"`
}

// NewMemory creates a new working memory with a message limit.
func NewMemory(maxMessages int) *Memory {
	if maxMessages <= 0 {
		maxMessages = 100
	}
	return &Memory{
		maxMsgs: maxMessages,
	}
}

// AddMessage appends a message to memory, evicting old messages if needed.
func (m *Memory) AddMessage(msg provider.Message) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.messages = append(m.messages, msg)

	// Keep system message + recent messages if we exceed the limit
	if len(m.messages) > m.maxMsgs {
		// Preserve first message (system) and last N messages
		keep := m.maxMsgs - 1
		m.messages = append(m.messages[:1], m.messages[len(m.messages)-keep:]...)
	}
}

// Messages returns a copy of all messages.
func (m *Memory) Messages() []provider.Message {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]provider.Message, len(m.messages))
	copy(result, m.messages)
	return result
}

// AddFinding records a security finding.
func (m *Memory) AddFinding(f Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = append(m.findings, f)
}

// Findings returns all recorded findings.
func (m *Memory) Findings() []Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Finding, len(m.findings))
	copy(result, m.findings)
	return result
}

// Clear resets the memory.
func (m *Memory) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = nil
	m.findings = nil
}
