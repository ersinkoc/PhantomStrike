package agent

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/ersinkoc/phantomstrike/internal/provider"
	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// LoopConfig configures the ReAct loop.
type LoopConfig struct {
	MaxIterations int
	SystemPrompt  string
	Tools         []provider.Tool
}

// Loop implements the ReAct (Reasoning + Acting) loop for agent execution.
type Loop struct {
	provider provider.Provider
	executor *tool.Executor
	config   LoopConfig
	history  []provider.Message
}

// History returns the message history from the loop.
func (l *Loop) History() []provider.Message {
	return l.history
}

// NewLoop creates a new ReAct loop.
func NewLoop(p provider.Provider, exec *tool.Executor, cfg LoopConfig) *Loop {
	return &Loop{
		provider: p,
		executor: exec,
		config:   cfg,
		history:  []provider.Message{},
	}
}

// Run executes the ReAct loop until goal is achieved or max iterations reached.
func (l *Loop) Run(ctx context.Context, initialMessage string, missionID *uuid.UUID, events chan<- SwarmEvent) error {
	l.history = append(l.history, provider.Message{
		Role:    "user",
		Content: initialMessage,
	})

	for i := 0; i < l.config.MaxIterations; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		slog.Debug("ReAct loop iteration", "iteration", i+1, "max", l.config.MaxIterations)

		// 1. OBSERVE + THINK: Send current state to LLM
		resp, err := l.provider.ChatCompletion(ctx, provider.ChatRequest{
			System:    l.config.SystemPrompt,
			Messages:  l.history,
			Tools:     l.config.Tools,
			MaxTokens: 4096,
		})
		if err != nil {
			return fmt.Errorf("LLM call at iteration %d: %w", i+1, err)
		}

		// 2. Record assistant response
		assistantMsg := provider.Message{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		}
		l.history = append(l.history, assistantMsg)

		// If there's text content, emit it
		if resp.Content != "" {
			events <- SwarmEvent{
				Type:  "thinking",
				Agent: "executor",
				Data:  map[string]any{"thought": resp.Content, "iteration": i + 1},
			}
		}

		// 3. Check if we're done (no tool calls = agent is finished)
		if len(resp.ToolCalls) == 0 {
			slog.Info("ReAct loop completed — no more tool calls",
				"iterations", i+1,
				"stop_reason", resp.StopReason,
			)
			return nil
		}

		// 4. ACT: Execute each tool call
		for _, tc := range resp.ToolCalls {
			events <- SwarmEvent{
				Type:  "tool_start",
				Agent: "executor",
				Data:  map[string]any{"tool": tc.Name, "params": tc.Input},
			}

			result, err := l.executor.Execute(ctx, tc.Name, tc.Input, missionID, nil)

			var toolResponse string
			if err != nil {
				toolResponse = fmt.Sprintf("Error executing %s: %v", tc.Name, err)
				events <- SwarmEvent{
					Type:  "tool_error",
					Agent: "executor",
					Data:  map[string]any{"tool": tc.Name, "error": err.Error()},
				}
			} else {
				toolResponse = result.Stdout
				if result.Stderr != "" {
					toolResponse += "\n--- STDERR ---\n" + result.Stderr
				}
				events <- SwarmEvent{
					Type:  "tool_complete",
					Agent: "executor",
					Data: map[string]any{
						"tool":      tc.Name,
						"exit_code": result.ExitCode,
						"duration":  result.Duration.Milliseconds(),
					},
				}
			}

			// 5. RECORD: Add tool result to history
			l.history = append(l.history, provider.Message{
				Role:       "tool",
				Content:    toolResponse,
				ToolCallID: tc.ID,
				Name:       tc.Name,
			})
		}
	}

	slog.Warn("ReAct loop hit max iterations", "max", l.config.MaxIterations)
	return fmt.Errorf("max iterations (%d) reached", l.config.MaxIterations)
}
