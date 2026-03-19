package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNotFound(t *testing.T) {
	// nil error should not be "not found"
	assert.False(t, IsNotFound(nil))
}
