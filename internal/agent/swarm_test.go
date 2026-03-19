package agent

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/provider"
	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// mockProvider implements provider.Provider for testing.
type mockProvider struct {
	name      string
	responses []*provider.ChatResponse
	callIdx   int
}

func (m *mockProvider) ChatCompletion(_ context.Context, _ provider.ChatRequest) (*provider.ChatResponse, error) {
	if m.callIdx < len(m.responses) {
		resp := m.responses[m.callIdx]
		m.callIdx++
		return resp, nil
	}
	// Default: return empty response with no tool calls (signals loop termination)
	return &provider.ChatResponse{Content: "Done.", StopReason: "end_turn"}, nil
}

func (m *mockProvider) StreamChatCompletion(_ context.Context, _ provider.ChatRequest) (<-chan provider.StreamEvent, error) {
	ch := make(chan provider.StreamEvent)
	close(ch)
	return ch, nil
}

func (m *mockProvider) Embedding(_ context.Context, _ []string) ([][]float64, error) {
	return nil, nil
}

func (m *mockProvider) Models(_ context.Context) ([]provider.Model, error) {
	return []provider.Model{{ID: "test-model", Name: "Test", ContextWindow: 4096}}, nil
}

func (m *mockProvider) Name() string              { return m.name }
func (m *mockProvider) SupportsToolCalling() bool  { return true }
func (m *mockProvider) MaxContextWindow(_ string) int { return 4096 }

func TestNewSwarm(t *testing.T) {
	cfg := config.AgentConfig{
		MaxIterations:    10,
		MaxParallelTools: 3,
		AutoReview:       true,
	}

	router := provider.NewRouter("mock", []string{"mock"})
	router.Register("mock", &mockProvider{name: "mock"})

	registry := tool.NewRegistry("", nil)
	swarm := NewSwarm(cfg, router, nil, registry)

	assert.NotNil(t, swarm)
	assert.Equal(t, 10, swarm.cfg.MaxIterations)
	assert.Equal(t, 3, swarm.cfg.MaxParallelTools)
	assert.True(t, swarm.cfg.AutoReview)
}

func TestSwarmDefaultPhases(t *testing.T) {
	cfg := config.AgentConfig{
		MaxIterations: 2,
		AutoReview:    false,
	}

	mp := &mockProvider{
		name: "mock",
		responses: []*provider.ChatResponse{
			{Content: "Plan: scan the target", StopReason: "end_turn"},
		},
	}

	router := provider.NewRouter("mock", []string{"mock"})
	router.Register("mock", mp)

	registry := tool.NewRegistry("", nil)
	swarm := NewSwarm(cfg, router, nil, registry)

	events := make(chan SwarmEvent, 100)
	missionID := uuid.New()

	// RunMission without registry/executor will fail at tool phase but
	// we're testing that default phases are set correctly
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// This will likely error due to nil executor in the ReAct loop,
	// but the swarm setup logic itself is what we're testing
	_ = swarm.RunMission(ctx, missionID, "http://test.com", nil, events)

	// Verify at least a phase_change event was emitted
	foundPhaseChange := false
	close(events)
	for evt := range events {
		if evt.Type == "phase_change" {
			foundPhaseChange = true
			break
		}
	}
	assert.True(t, foundPhaseChange, "expected at least one phase_change event")
}

func TestPhaseConstants(t *testing.T) {
	assert.Equal(t, Phase("recon"), PhaseRecon)
	assert.Equal(t, Phase("scanning"), PhaseScanning)
	assert.Equal(t, Phase("exploitation"), PhaseExploit)
	assert.Equal(t, Phase("post_exploit"), PhasePostExploit)
	assert.Equal(t, Phase("reporting"), PhaseReporting)
}

func TestSwarmEvent(t *testing.T) {
	evt := SwarmEvent{
		Type:  "thinking",
		Agent: "planner",
		Data:  map[string]any{"phase": "recon"},
	}
	assert.Equal(t, "thinking", evt.Type)
	assert.Equal(t, "planner", evt.Agent)
}

func TestExecutionPlan(t *testing.T) {
	plan := &ExecutionPlan{
		Phase:   PhaseRecon,
		RawPlan: "scan ports",
		Steps: []PlanStep{
			{ToolName: "nmap", Parameters: map[string]any{"target": "10.0.0.1"}, Priority: 1},
		},
	}
	assert.Equal(t, PhaseRecon, plan.Phase)
	assert.Len(t, plan.Steps, 1)
	assert.Equal(t, "nmap", plan.Steps[0].ToolName)
}
