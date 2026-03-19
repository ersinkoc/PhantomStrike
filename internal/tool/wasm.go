package tool

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WASMRunner executes tools as WebAssembly modules using the wazero runtime.
type WASMRunner struct {
	enabled bool
}

// NewWASMRunner creates a new WASM runner.
func NewWASMRunner(enabled bool) *WASMRunner {
	return &WASMRunner{enabled: enabled}
}

// Run executes a WASM binary with input parameters and returns the output.
// The input is passed via stdin; stdout and stderr are captured into ExecResult.
func (w *WASMRunner) Run(ctx context.Context, wasmPath string, input []byte) (*ExecResult, error) {
	if !w.enabled {
		return nil, fmt.Errorf("WASM runner is disabled")
	}

	// Read the WASM binary
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("reading WASM file %s: %w", wasmPath, err)
	}

	// Apply a timeout for execution
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Create a new wazero runtime
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)

	// Instantiate WASI for stdin/stdout/stderr support
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	// Prepare stdin, stdout, stderr buffers
	stdin := bytes.NewReader(input)
	var stdout, stderr bytes.Buffer

	// Configure the module with WASI I/O
	moduleCfg := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithStartFunctions("_start")

	slog.Debug("running WASM module", "path", wasmPath, "input_size", len(input))

	// Instantiate and run the module
	_, err = runtime.InstantiateWithConfig(ctx, wasmBytes, moduleCfg)

	result := &ExecResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
			result.ExitCode = -1
			return result, fmt.Errorf("WASM execution timed out")
		}
		// wazero may return an exit error with a non-zero code
		result.ExitCode = 1
		result.Status = "failed"
		slog.Debug("WASM execution error", "error", err, "stderr", result.Stderr)
		return result, nil
	}

	result.ExitCode = 0
	result.Status = "completed"
	return result, nil
}
