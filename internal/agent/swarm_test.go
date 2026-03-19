package agent

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSwarm(t *testing.T) {
	llm := NewMockLLM()
	swarm := NewSwarm(llm, Config{
		MaxIterations:    10,
		MaxParallelTools: 3,
	})

	assert.NotNil(t, swarm)
	assert.Equal(t, 10, swarm.config.MaxIterations)
	assert.Equal(t, 3, swarm.config.MaxParallelTools)
}

func TestSwarmExecute(t *testing.T) {
	llm := NewMockLLM()
	swarm := NewSwarm(llm, Config{
		MaxIterations: 5,
	})

	mission := &Mission{
		ID:      "test-123",
		Target:  "http://test.com",
		Mode:    "passive",
		Context: make(map[string]interface{}),
	}

	// Mock LLM response
	llm.AddResponse("planner", &LLMResponse{
		Content: `{"phases": ["recon", "scan"], "reasoning": "Test plan"}`,
	})

	ctx := context.Background()
	result, err := swarm.Execute(ctx, mission)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-123", result.MissionID)
}

func TestReActLoop(t *testing.T) {
	loop := NewReActLoop(Config{MaxIterations: 3})

	// Test iteration limit
	for i := 0; i < 5; i++ {
		shouldContinue := loop.Step()
		if i < 2 {
			assert.True(t, shouldContinue)
		} else {
			assert.False(t, shouldContinue)
		}
	}

	assert.True(t, loop.ReachedLimit())
}

func TestToolExecution(t *testing.T) {
	exec := NewToolExecutor()

	tool := &Tool{
		Name:    "test-tool",
		Command: "echo",
		Args:    []string{"hello"},
	}

	ctx := context.Background()
	result, err := exec.Run(ctx, tool, map[string]interface{}{})

	assert.NoError(t, err)
	assert.Contains(t, result.Output, "hello")
	assert.Equal(t, 0, result.ExitCode)
}

// MockLLM for testing
type MockLLM struct {
	responses map[string][]*LLMResponse
	callCount map[string]int
}

func NewMockLLM() *MockLLM {
	return &MockLLM{
		responses: make(map[string][]*LLMResponse),
		callCount: make(map[string]int),
	}
}

func (m *MockLLM) AddResponse(agentType string, resp *LLMResponse) {
	m.responses[agentType] = append(m.responses[agentType], resp)
}

func (m *MockLLM) Complete(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	agentType := req.AgentType
	count := m.callCount[agentType]
	m.callCount[agentType]++

	if resps, ok := m.responses[agentType]; ok && count < len(resps) {
		return resps[count], nil
	}

	return &LLMResponse{Content: "{}"}, nil
}
