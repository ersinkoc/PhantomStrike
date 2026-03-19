package tool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCommandWithStringParam(t *testing.T) {
	def := &Definition{
		Command: "nmap",
		Args:    []string{"-sV"},
		Parameters: []ParamDef{
			{Name: "target", Flag: "-t", Required: true},
			{Name: "ports", Flag: "-p", Required: false},
		},
	}

	params := map[string]any{
		"target": "10.0.0.1",
		"ports":  "80,443",
	}

	cmd, args := BuildCommand(def, params)
	assert.Equal(t, "nmap", cmd)
	assert.Contains(t, args, "-sV")
	assert.Contains(t, args, "-t")
	assert.Contains(t, args, "10.0.0.1")
	assert.Contains(t, args, "-p")
	assert.Contains(t, args, "80,443")
}

func TestBuildCommandWithBoolParam(t *testing.T) {
	def := &Definition{
		Command: "scanner",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "verbose", Flag: "-v", Type: "boolean"},
			{Name: "quiet", Flag: "-q", Type: "boolean"},
		},
	}

	params := map[string]any{
		"verbose": true,
		"quiet":   false,
	}

	cmd, args := BuildCommand(def, params)
	assert.Equal(t, "scanner", cmd)
	assert.Contains(t, args, "-v")
	// quiet is false, so -q should NOT be in args
	assert.NotContains(t, args, "-q")
}

func TestBuildCommandWithNumericParam(t *testing.T) {
	def := &Definition{
		Command: "tool",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "threads", Flag: "--threads", Type: "number"},
			{Name: "rate", Flag: "--rate", Type: "number"},
		},
	}

	params := map[string]any{
		"threads": float64(10),
		"rate":    42,
	}

	cmd, args := BuildCommand(def, params)
	assert.Equal(t, "tool", cmd)
	assert.Contains(t, args, "--threads")
	assert.Contains(t, args, "10")
	assert.Contains(t, args, "--rate")
	assert.Contains(t, args, "42")
}

func TestBuildCommandWithNoFlag(t *testing.T) {
	def := &Definition{
		Command: "echo",
		Args:    []string{"hello"},
		Parameters: []ParamDef{
			{Name: "target", Flag: "", Required: true},
		},
	}

	params := map[string]any{
		"target": "world",
	}

	cmd, args := BuildCommand(def, params)
	assert.Equal(t, "echo", cmd)
	// target has no flag, so only original args should be present
	assert.Equal(t, []string{"hello"}, args)
}

func TestBuildCommandWithDefaultParam(t *testing.T) {
	def := &Definition{
		Command: "scan",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "format", Flag: "--format", Default: "json"},
		},
	}

	// No params provided — should use default
	cmd, args := BuildCommand(def, map[string]any{})
	assert.Equal(t, "scan", cmd)
	assert.Contains(t, args, "--format")
	assert.Contains(t, args, "json")
}

func TestBuildCommandWithEmptyStringParam(t *testing.T) {
	def := &Definition{
		Command: "tool",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "output", Flag: "-o", Type: "string"},
		},
	}

	params := map[string]any{
		"output": "",
	}

	_, args := BuildCommand(def, params)
	// Empty string should not add the flag
	assert.NotContains(t, args, "-o")
}

func TestBuildCommandWithMissingParamNoDefault(t *testing.T) {
	def := &Definition{
		Command: "tool",
		Args:    []string{"base"},
		Parameters: []ParamDef{
			{Name: "optional", Flag: "--opt", Type: "string"},
		},
	}

	// No params and no default — should skip
	cmd, args := BuildCommand(def, map[string]any{})
	assert.Equal(t, "tool", cmd)
	assert.Equal(t, []string{"base"}, args)
}

func TestBuildCommandPreservesBaseArgs(t *testing.T) {
	def := &Definition{
		Command: "nmap",
		Args:    []string{"-sV", "-sC", "--open"},
		Parameters: []ParamDef{
			{Name: "target", Flag: "-t"},
		},
	}

	params := map[string]any{
		"target": "192.168.1.1",
	}

	cmd, args := BuildCommand(def, params)
	assert.Equal(t, "nmap", cmd)
	// Base args should come first
	assert.Equal(t, "-sV", args[0])
	assert.Equal(t, "-sC", args[1])
	assert.Equal(t, "--open", args[2])
}

func TestTruncateShortString(t *testing.T) {
	result := truncate("hello", 10)
	assert.Equal(t, "hello", result)
}

func TestTruncateExactLength(t *testing.T) {
	result := truncate("12345", 5)
	assert.Equal(t, "12345", result)
}

func TestTruncateLongString(t *testing.T) {
	result := truncate("hello world, this is a long string", 10)
	assert.Equal(t, "hello worl\n... [truncated]", result)
}

func TestTruncateEmptyString(t *testing.T) {
	result := truncate("", 10)
	assert.Equal(t, "", result)
}

func TestTruncateZeroMax(t *testing.T) {
	result := truncate("hello", 0)
	assert.Equal(t, "\n... [truncated]", result)
}

func TestNewExecutor(t *testing.T) {
	registry := NewRegistry("", nil)

	// Without docker
	e := NewExecutor(registry, nil, false)
	assert.NotNil(t, e)
	assert.NotNil(t, e.registry)
	assert.NotNil(t, e.process)
	assert.NotNil(t, e.wasm)
	assert.Nil(t, e.docker)

	// With docker
	e2 := NewExecutor(registry, nil, true)
	assert.NotNil(t, e2)
	assert.NotNil(t, e2.docker)
}
