package tool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry("", nil)
	assert.NotNil(t, r)
	assert.Empty(t, r.List())
}

func TestRegistryLoadYAML(t *testing.T) {
	tmp := t.TempDir()

	// Create a test tool YAML
	toolYAML := `
name: "test-tool"
version: "1.0.0"
category: "test"
command: "echo"
args: ["hello"]
short_description: "A test tool"
description: "Tool for testing"
parameters:
  - name: "target"
    type: "string"
    description: "Target host"
    required: true
    flag: "-t"
enabled: true
`
	err := os.MkdirAll(filepath.Join(tmp, "test"), 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmp, "test", "test-tool.yaml"), []byte(toolYAML), 0644)
	require.NoError(t, err)

	r := NewRegistry(tmp, nil)
	err = r.LoadAll()
	require.NoError(t, err)

	// Verify tool was loaded
	tools := r.List()
	assert.Len(t, tools, 1)
	assert.Equal(t, "test-tool", tools[0].Name)
	assert.Equal(t, "test", tools[0].Category)
	assert.True(t, tools[0].Enabled)
	assert.Len(t, tools[0].Parameters, 1)
	assert.Equal(t, "target", tools[0].Parameters[0].Name)
}

func TestRegistryGet(t *testing.T) {
	tmp := t.TempDir()
	toolYAML := `
name: "nmap-test"
version: "1.0.0"
category: "network"
command: "nmap"
short_description: "Port scanner"
enabled: true
`
	err := os.WriteFile(filepath.Join(tmp, "nmap.yaml"), []byte(toolYAML), 0644)
	require.NoError(t, err)

	r := NewRegistry(tmp, nil)
	r.LoadAll()

	def, ok := r.Get("nmap-test")
	assert.True(t, ok)
	assert.Equal(t, "nmap-test", def.Name)

	_, ok = r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryEmptyDir(t *testing.T) {
	tmp := t.TempDir()

	r := NewRegistry(tmp, nil)
	err := r.LoadAll()
	require.NoError(t, err)
	assert.Empty(t, r.List())
}

func TestRegistryNonexistentDir(t *testing.T) {
	r := NewRegistry("/nonexistent/path", nil)
	err := r.LoadAll()
	// Should not error — just load nothing
	require.NoError(t, err)
	assert.Empty(t, r.List())
}

func TestBuildCommandBasic(t *testing.T) {
	def := &Definition{
		Command: "nmap",
		Args:    []string{"-sV"},
		Parameters: []ParamDef{
			{Name: "target", Flag: "", Required: true},
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
}

func TestDefinitionStructure(t *testing.T) {
	def := Definition{
		Name:             "sqlmap",
		Version:          "1.0.0",
		Category:         "web/injection",
		Tags:             []string{"sql", "injection"},
		Command:          "sqlmap",
		ShortDescription: "SQL injection scanner",
		Enabled:          true,
		Docker: DockerDef{
			Image:       "phantomstrike/sqlmap:latest",
			Network:     "isolated",
			MemoryLimit: "512m",
		},
	}

	assert.Equal(t, "sqlmap", def.Name)
	assert.Equal(t, "web/injection", def.Category)
	assert.Equal(t, "phantomstrike/sqlmap:latest", def.Docker.Image)
	assert.True(t, def.Enabled)
}
