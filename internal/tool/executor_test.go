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
	// target has no flag (positional), so it is appended after base args
	assert.Equal(t, []string{"hello", "world"}, args)
}

func TestBuildCommandWithNoFlagSpaceSplit(t *testing.T) {
	def := &Definition{
		Command: "nmap",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "flags", Flag: "", Required: false},
			{Name: "target", Flag: "", Required: true},
		},
	}

	params := map[string]any{
		"flags":  "-sV -T4 -O",
		"target": "192.168.1.1",
	}

	cmd, args := BuildCommand(def, params)
	assert.Equal(t, "nmap", cmd)
	// Space-separated positional values are split into individual args
	assert.Equal(t, []string{"-sV", "-T4", "-O", "192.168.1.1"}, args)
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

func TestBuildCommandDnsenum(t *testing.T) {
	// dnsenum: positional target, static args
	def := &Definition{
		Command: "dnsenum",
		Args:    []string{"-o", "/output/dnsenum-results.xml", "--threads", "5"},
		Parameters: []ParamDef{
			{Name: "target", Flag: "", Required: true},
		},
	}
	cmd, args := BuildCommand(def, map[string]any{"target": "example.com"})
	assert.Equal(t, "dnsenum", cmd)
	assert.Equal(t, []string{"-o", "/output/dnsenum-results.xml", "--threads", "5", "example.com"}, args)
}

func TestBuildCommandSqlmap(t *testing.T) {
	// sqlmap: flagged target with --batch in args
	def := &Definition{
		Command: "sqlmap",
		Args:    []string{"--batch"},
		Parameters: []ParamDef{
			{Name: "target", Flag: "-u", Required: true},
		},
	}
	cmd, args := BuildCommand(def, map[string]any{"target": "http://target.com/page?id=1"})
	assert.Equal(t, "sqlmap", cmd)
	assert.Equal(t, []string{"--batch", "-u", "http://target.com/page?id=1"}, args)
}

func TestBuildCommandDirb(t *testing.T) {
	// dirb: multiple positional args (URL + wordlist + options)
	def := &Definition{
		Command: "dirb",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "target", Flag: "", Required: true},
			{Name: "wordlist", Flag: "", Default: "/usr/share/dirb/wordlists/common.txt"},
			{Name: "options", Flag: "", Default: "-r -S"},
		},
	}
	cmd, args := BuildCommand(def, map[string]any{"target": "http://target.com/"})
	assert.Equal(t, "dirb", cmd)
	// target + default wordlist + default options (split by space)
	assert.Equal(t, []string{"http://target.com/", "/usr/share/dirb/wordlists/common.txt", "-r", "-S"}, args)
}

func TestBuildCommandMedusa(t *testing.T) {
	// medusa: all flagged params
	def := &Definition{
		Command: "medusa",
		Args:    []string{},
		Parameters: []ParamDef{
			{Name: "target", Flag: "-h", Required: true},
			{Name: "username", Flag: "-u"},
			{Name: "passlist", Flag: "-P", Default: "/wordlists/passwords.txt"},
			{Name: "module", Flag: "-M", Required: true},
		},
	}
	cmd, args := BuildCommand(def, map[string]any{
		"target":   "192.168.1.1",
		"username": "admin",
		"module":   "ssh",
	})
	assert.Equal(t, "medusa", cmd)
	assert.Contains(t, args, "-h")
	assert.Contains(t, args, "192.168.1.1")
	assert.Contains(t, args, "-u")
	assert.Contains(t, args, "admin")
	assert.Contains(t, args, "-P")
	assert.Contains(t, args, "/wordlists/passwords.txt")
	assert.Contains(t, args, "-M")
	assert.Contains(t, args, "ssh")
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
