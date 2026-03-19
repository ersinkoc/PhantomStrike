package tool

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// DockerRunner executes tools inside isolated Docker containers.
type DockerRunner struct{}

// NewDockerRunner creates a new Docker runner.
func NewDockerRunner() *DockerRunner {
	return &DockerRunner{}
}

// Run executes a tool inside a Docker container.
func (d *DockerRunner) Run(ctx context.Context, def *Definition, command string, args []string) (*ExecResult, error) {
	timeout := 5 * time.Minute
	if def.Docker.Timeout != "" {
		if parsed, err := time.ParseDuration(def.Docker.Timeout); err == nil {
			timeout = parsed
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build docker run command
	dockerArgs := []string{
		"run", "--rm",
		"--network", coalesce(def.Docker.Network, "none"),
		"--read-only",
		"--no-new-privileges",
		"--user", "1000:1000",
	}

	// Memory limit
	if def.Docker.MemoryLimit != "" {
		dockerArgs = append(dockerArgs, "--memory", def.Docker.MemoryLimit)
	} else {
		dockerArgs = append(dockerArgs, "--memory", "512m")
	}

	// CPU limit
	if def.Docker.CPULimit != "" {
		dockerArgs = append(dockerArgs, "--cpus", def.Docker.CPULimit)
	} else {
		dockerArgs = append(dockerArgs, "--cpus", "1.0")
	}

	// Tmpfs for writable directories
	dockerArgs = append(dockerArgs, "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m")

	// Image
	image := def.Docker.Image
	if image == "" {
		return nil, fmt.Errorf("docker image not specified for tool %s", def.Name)
	}
	dockerArgs = append(dockerArgs, image)

	// Tool command and args
	dockerArgs = append(dockerArgs, command)
	dockerArgs = append(dockerArgs, args...)

	slog.Debug("running docker container",
		"tool", def.Name,
		"image", image,
		"command", command,
		"args", strings.Join(args, " "),
	)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
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
			return result, fmt.Errorf("docker container timed out after %v", timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			result.Status = "failed"
			return result, nil
		}
		return result, fmt.Errorf("docker run failed: %w", err)
	}

	result.ExitCode = 0
	result.Status = "completed"
	return result, nil
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
