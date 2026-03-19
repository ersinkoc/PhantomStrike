package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionDefaults(t *testing.T) {
	// Default values when not set via ldflags
	assert.Equal(t, "dev", Version)
	assert.Equal(t, "unknown", Commit)
	assert.Equal(t, "unknown", Date)
}

func TestVersionVariablesAreStrings(t *testing.T) {
	assert.IsType(t, "", Version)
	assert.IsType(t, "", Commit)
	assert.IsType(t, "", Date)
}

func TestVersionNotEmpty(t *testing.T) {
	assert.NotEmpty(t, Version)
	assert.NotEmpty(t, Commit)
	assert.NotEmpty(t, Date)
}
