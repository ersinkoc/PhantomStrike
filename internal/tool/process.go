package tool

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// ProcessRunner executes tools as local processes (fallback when Docker is unavailable).
type ProcessRunner struct{}

// NewProcessRunner creates a new process runner.
func NewProcessRunner() *ProcessRunner {
	return &ProcessRunner{}
}

// Run executes a command as a local process with timeout.
func (p *ProcessRunner) Run(ctx context.Context, command string, args []string, timeout time.Duration) (*ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &ExecResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
			result.ExitCode = -1
			return result, fmt.Errorf("command timed out after %v", timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			result.Status = "failed"
			return result, nil // Non-zero exit is not an error for us
		}
		return result, fmt.Errorf("running command: %w", err)
	}

	result.ExitCode = 0
	result.Status = "completed"
	return result, nil
}
