package tool

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExecResult represents the result of a tool execution.
type ExecResult struct {
	ID          uuid.UUID     `json:"id"`
	ToolName    string        `json:"tool_name"`
	Status      string        `json:"status"` // completed, failed, timeout
	Stdout      string        `json:"stdout"`
	Stderr      string        `json:"stderr"`
	ExitCode    int           `json:"exit_code"`
	Duration    time.Duration `json:"duration_ms"`
	ArtifactID  *uuid.UUID    `json:"artifact_id,omitempty"`
}

// Executor coordinates tool execution across different backends.
type Executor struct {
	registry *Registry
	pool     *pgxpool.Pool
	docker   *DockerRunner
	process  *ProcessRunner
	wasm     *WASMRunner
}

// NewExecutor creates a new tool executor.
func NewExecutor(registry *Registry, pool *pgxpool.Pool, dockerEnabled bool) *Executor {
	e := &Executor{
		registry: registry,
		pool:     pool,
		process:  NewProcessRunner(),
		wasm:     NewWASMRunner(true),
	}
	if dockerEnabled {
		e.docker = NewDockerRunner()
	}
	return e
}

// Execute runs a tool with the given parameters.
func (e *Executor) Execute(ctx context.Context, toolName string, params map[string]any, missionID, conversationID *uuid.UUID) (*ExecResult, error) {
	def, ok := e.registry.Get(toolName)
	if !ok {
		return nil, fmt.Errorf("tool %q not found", toolName)
	}

	if !def.Enabled {
		return nil, fmt.Errorf("tool %q is disabled", toolName)
	}

	// Create execution record
	execID := uuid.New()
	mode := "process"
	if e.wasm != nil && def.WASMPath != "" {
		mode = "wasm"
	} else if e.docker != nil && def.Docker.Image != "" {
		mode = "docker"
	}

	_, err := e.pool.Exec(ctx,
		`INSERT INTO tool_executions (id, tool_name, parameters, status, execution_mode, mission_id, conversation_id, started_at)
		 VALUES ($1, $2, $3, 'running', $4, $5, $6, $7)`,
		execID, toolName, params, mode, missionID, conversationID, time.Now(),
	)
	if err != nil {
		slog.Warn("failed to record tool execution", "error", err)
	}

	// Build command
	cmd, args := BuildCommand(def, params)

	// Execute
	start := time.Now()
	var result *ExecResult

	switch mode {
	case "wasm":
		// For WASM, serialize parameters as JSON input
		input := []byte(fmt.Sprintf(`{"command":%q,"args":%q}`, cmd, args))
		result, err = e.wasm.Run(ctx, def.WASMPath, input)
	case "docker":
		result, err = e.docker.Run(ctx, def, cmd, args)
	default:
		result, err = e.process.Run(ctx, cmd, args, 5*time.Minute)
	}

	duration := time.Since(start)

	if err != nil {
		// Record failure
		_, _ = e.pool.Exec(ctx,
			`UPDATE tool_executions SET status = 'failed', stderr = $1, duration_ms = $2, completed_at = $3 WHERE id = $4`,
			err.Error(), duration.Milliseconds(), time.Now(), execID,
		)
		return nil, fmt.Errorf("executing %s: %w", toolName, err)
	}

	result.ID = execID
	result.ToolName = toolName
	result.Duration = duration

	// Record success
	status := "completed"
	if result.ExitCode != 0 {
		status = "failed"
	}
	result.Status = status

	_, _ = e.pool.Exec(ctx,
		`UPDATE tool_executions SET status = $1, stdout = $2, stderr = $3, exit_code = $4, duration_ms = $5, completed_at = $6 WHERE id = $7`,
		status, truncate(result.Stdout, 500000), truncate(result.Stderr, 50000),
		result.ExitCode, duration.Milliseconds(), time.Now(), execID,
	)

	// Update tool stats
	_, _ = e.pool.Exec(ctx,
		`UPDATE tool_registry SET last_used = NOW(),
			avg_exec_time = COALESCE((avg_exec_time * install_count + $1) / (install_count + 1), $1),
			install_count = install_count + 1
		 WHERE name = $2`,
		duration.Milliseconds(), toolName,
	)

	slog.Info("tool execution completed",
		"tool", toolName,
		"status", status,
		"exit_code", result.ExitCode,
		"duration_ms", duration.Milliseconds(),
	)

	return result, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}
