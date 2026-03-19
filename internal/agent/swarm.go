package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/ersinkoc/phantomstrike/internal/provider"
	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// Phase represents a mission phase.
type Phase string

const (
	PhaseRecon       Phase = "recon"
	PhaseScanning    Phase = "scanning"
	PhaseExploit     Phase = "exploitation"
	PhasePostExploit Phase = "post_exploit"
	PhaseReporting   Phase = "reporting"
)

// SwarmEvent represents an event emitted during swarm execution.
type SwarmEvent struct {
	Type    string `json:"type"` // thinking, tool_start, tool_complete, vuln_found, phase_change, done
	Agent   string `json:"agent"`
	Data    any    `json:"data"`
}

// Swarm coordinates the multi-agent system (planner, executor, reviewer).
type Swarm struct {
	cfg      config.AgentConfig
	router   *provider.Router
	executor *tool.Executor
	registry *tool.Registry
	mu       sync.Mutex
	cancels  map[uuid.UUID]context.CancelFunc
	cancelMu sync.Mutex
}

// NewSwarm creates a new agent swarm coordinator.
func NewSwarm(cfg config.AgentConfig, router *provider.Router, executor *tool.Executor, registry *tool.Registry) *Swarm {
	return &Swarm{
		cfg:      cfg,
		router:   router,
		executor: executor,
		registry: registry,
		cancels:  make(map[uuid.UUID]context.CancelFunc),
	}
}

// GetRouter returns the provider router used by the swarm.
func (s *Swarm) GetRouter() *provider.Router {
	return s.router
}

// GetExecutor returns the tool executor used by the swarm.
func (s *Swarm) GetExecutor() *tool.Executor {
	return s.executor
}

// CancelMission cancels a running mission by its ID.
func (s *Swarm) CancelMission(missionID uuid.UUID) {
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	if cancel, ok := s.cancels[missionID]; ok {
		cancel()
		delete(s.cancels, missionID)
		slog.Info("mission cancelled via swarm", "mission_id", missionID)
	}
}

// RunMission starts autonomous execution of a mission.
func (s *Swarm) RunMission(ctx context.Context, missionID uuid.UUID, target any, phases []Phase, events chan<- SwarmEvent) error {
	// Create a cancellable context and register it
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.cancelMu.Lock()
	s.cancels[missionID] = cancel
	s.cancelMu.Unlock()

	defer func() {
		s.cancelMu.Lock()
		delete(s.cancels, missionID)
		s.cancelMu.Unlock()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Info("starting mission swarm", "mission_id", missionID, "phases", phases)

	if len(phases) == 0 {
		phases = []Phase{PhaseRecon, PhaseScanning, PhaseExploit, PhaseReporting}
	}

	for _, phase := range phases {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		events <- SwarmEvent{Type: "phase_change", Agent: "swarm", Data: map[string]any{"phase": phase}}
		slog.Info("executing phase", "phase", phase, "mission_id", missionID)

		if err := s.executePhase(ctx, missionID, phase, target, events); err != nil {
			slog.Error("phase failed", "phase", phase, "error", err)
			return fmt.Errorf("phase %s failed: %w", phase, err)
		}
	}

	events <- SwarmEvent{Type: "done", Agent: "swarm", Data: map[string]any{"mission_id": missionID}}
	return nil
}

// executePhase runs a single mission phase through the agent loop.
func (s *Swarm) executePhase(ctx context.Context, missionID uuid.UUID, phase Phase, target any, events chan<- SwarmEvent) error {
	// 1. Planner: create strategy for this phase
	plan, err := s.plan(ctx, phase, target, events)
	if err != nil {
		return fmt.Errorf("planning: %w", err)
	}

	// 2. Executor: execute the plan
	results, err := s.execute(ctx, missionID, plan, events)
	if err != nil {
		return fmt.Errorf("executing: %w", err)
	}

	// 3. Reviewer: review results
	if s.cfg.AutoReview {
		if err := s.review(ctx, results, events); err != nil {
			slog.Warn("review failed", "error", err)
		}
	}

	return nil
}

// plan uses the planner agent to create a strategy.
func (s *Swarm) plan(ctx context.Context, phase Phase, target any, events chan<- SwarmEvent) (*ExecutionPlan, error) {
	events <- SwarmEvent{Type: "thinking", Agent: "planner", Data: map[string]any{"phase": phase}}

	// Get planner provider
	p, err := s.getAgentProvider("planner")
	if err != nil {
		return nil, err
	}

	systemPrompt := fmt.Sprintf(`You are the PhantomStrike Planner Agent. Your role is to create a security testing strategy for the %s phase.
Analyze the target and select appropriate tools to use. Return a JSON plan with tool names and parameters.
Available tools: %v`, phase, s.getToolNames())

	resp, err := p.ChatCompletion(ctx, provider.ChatRequest{
		System: systemPrompt,
		Messages: []provider.Message{
			{Role: "user", Content: fmt.Sprintf("Create a %s plan for target: %v", phase, target)},
		},
		MaxTokens: s.cfg.ThinkingBudget,
	})
	if err != nil {
		return nil, fmt.Errorf("planner LLM call: %w", err)
	}

	events <- SwarmEvent{Type: "thinking", Agent: "planner", Data: map[string]any{"plan": resp.Content}}

	// Parse plan from response (simplified — in production, use tool calling)
	plan := &ExecutionPlan{
		Phase:   phase,
		RawPlan: resp.Content,
	}

	return plan, nil
}

// execute runs tools based on the plan using the ReAct loop.
func (s *Swarm) execute(ctx context.Context, missionID uuid.UUID, plan *ExecutionPlan, events chan<- SwarmEvent) ([]*tool.ExecResult, error) {
	events <- SwarmEvent{Type: "thinking", Agent: "executor", Data: map[string]any{"phase": plan.Phase}}

	// Get executor provider (default)
	p, err := s.getAgentProvider("executor")
	if err != nil {
		return nil, err
	}

	// Get available tools for this phase
	tools := s.getToolsForPhase(plan.Phase)

	// Build system prompt for the executor agent
	systemPrompt := fmt.Sprintf(`You are the PhantomStrike Executor Agent. You are in the %s phase of a security assessment.
Your role is to execute security tools, analyze their output, and decide on next steps.

Available tools: %v

Follow this process:
1. Analyze the current situation and available information
2. Choose the most appropriate tool to run next
3. Execute the tool and observe the results
4. Based on the results, decide if you need to:
   - Run another tool to gather more information
   - Report findings if you discover vulnerabilities
   - Stop if the phase objectives are complete

Be thorough but efficient. Always explain your reasoning before taking action.`, plan.Phase, s.getToolNames())

	// Create ReAct loop
	loop := NewLoop(p, s.executor, LoopConfig{
		MaxIterations: s.cfg.MaxIterations,
		SystemPrompt:  systemPrompt,
		Tools:         tools,
	})

	// Build initial message with target and plan context
	initialMsg := fmt.Sprintf("Phase: %s\nPlan: %s", plan.Phase, plan.RawPlan)

	// Run the ReAct loop
	if err := loop.Run(ctx, initialMsg, &missionID, events); err != nil {
		return nil, fmt.Errorf("ReAct loop failed: %w", err)
	}

	// Collect results from loop history (tool execution results)
	var results []*tool.ExecResult
	for _, msg := range loop.history {
		if msg.Role == "tool" && msg.Content != "" {
			results = append(results, &tool.ExecResult{
				ToolName: msg.Name,
				Stdout:   msg.Content,
				Status:   "completed",
			})
		}
	}

	return results, nil
}

// review validates findings.
func (s *Swarm) review(ctx context.Context, results []*tool.ExecResult, events chan<- SwarmEvent) error {
	events <- SwarmEvent{Type: "thinking", Agent: "reviewer", Data: map[string]any{"reviewing": len(results)}}

	if len(results) == 0 {
		return nil
	}

	p, err := s.getAgentProvider("reviewer")
	if err != nil {
		return err
	}

	_ = p // Reviewer will analyze results and validate findings
	return nil
}

func (s *Swarm) getAgentProvider(agentType string) (provider.Provider, error) {
	p, ok := s.router.Get(agentType)
	if ok {
		return p, nil
	}
	return s.router.Default()
}

func (s *Swarm) getToolNames() []string {
	defs := s.registry.List()
	names := make([]string, 0, len(defs))
	for _, d := range defs {
		if d.Enabled {
			names = append(names, d.Name)
		}
	}
	return names
}

// getToolsForPhase returns tool definitions for a specific phase.
func (s *Swarm) getToolsForPhase(phase Phase) []provider.Tool {
	allDefs := s.registry.List()
	var tools []provider.Tool

	for _, def := range allDefs {
		if !def.Enabled {
			continue
		}

		// Filter by phase if specified in tool metadata
		if def.Phase != "" && def.Phase != string(phase) {
			continue
		}

		// Build input schema from parameters
		properties := make(map[string]any)
		var required []string
		for _, p := range def.Parameters {
			prop := map[string]any{
				"type":        p.Type,
				"description": p.Description,
			}
			if len(p.Enum) > 0 {
				prop["enum"] = p.Enum
			}
			if p.Default != nil {
				prop["default"] = p.Default
			}
			properties[p.Name] = prop
			if p.Required {
				required = append(required, p.Name)
			}
		}

		tools = append(tools, provider.Tool{
			Name:        def.Name,
			Description: def.ShortDescription,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": properties,
				"required":   required,
			},
		})
	}

	return tools
}

// ExecutionPlan represents the planner's output.
type ExecutionPlan struct {
	Phase   Phase
	RawPlan string
	Steps   []PlanStep
}

// PlanStep represents a single step in the execution plan.
type PlanStep struct {
	ToolName   string         `json:"tool_name"`
	Parameters map[string]any `json:"parameters"`
	Priority   int            `json:"priority"`
	DependsOn  []string       `json:"depends_on,omitempty"`
}
