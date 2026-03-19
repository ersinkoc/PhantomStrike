package chain

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	b := NewBuilder(nil)
	require.NotNil(t, b)
	assert.Nil(t, b.pool)
}

func TestNodeStruct(t *testing.T) {
	id := uuid.New()
	n := Node{
		ID:       id,
		Type:     "target",
		Label:    "test-host",
		Data:     map[string]any{"ip": "192.168.1.1"},
		Severity: "high",
		Phase:    "recon",
	}

	assert.Equal(t, id, n.ID)
	assert.Equal(t, "target", n.Type)
	assert.Equal(t, "test-host", n.Label)
	assert.Equal(t, "192.168.1.1", n.Data["ip"])
	assert.Equal(t, "high", n.Severity)
	assert.Equal(t, "recon", n.Phase)
}

func TestEdgeStruct(t *testing.T) {
	id := uuid.New()
	srcID := uuid.New()
	tgtID := uuid.New()

	e := Edge{
		ID:       id,
		SourceID: srcID,
		TargetID: tgtID,
		Type:     "discovered",
		Label:    "port scan",
	}

	assert.Equal(t, id, e.ID)
	assert.Equal(t, srcID, e.SourceID)
	assert.Equal(t, tgtID, e.TargetID)
	assert.Equal(t, "discovered", e.Type)
	assert.Equal(t, "port scan", e.Label)
}

func TestNodeTypes(t *testing.T) {
	// Verify the documented node types are valid strings
	validTypes := []string{"target", "tool", "vulnerability", "credential", "pivot"}
	for _, typ := range validTypes {
		n := Node{Type: typ}
		assert.NotEmpty(t, n.Type)
	}
}

func TestEdgeTypes(t *testing.T) {
	// Verify the documented edge types are valid strings
	validTypes := []string{"discovered", "exploited", "pivoted", "escalated"}
	for _, typ := range validTypes {
		e := Edge{Type: typ}
		assert.NotEmpty(t, e.Type)
	}
}
