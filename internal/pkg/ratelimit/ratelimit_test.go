package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	l := New(10, time.Second)
	defer l.Stop()

	require.NotNil(t, l)
	assert.Equal(t, 10, l.rate)
	assert.Equal(t, time.Second, l.window)
	assert.NotNil(t, l.visitors)
	assert.Empty(t, l.visitors)
}

func TestAllow_WithinRate(t *testing.T) {
	l := New(3, time.Second)
	defer l.Stop()

	// First 3 requests should be allowed
	assert.True(t, l.Allow("192.168.1.1"))
	assert.True(t, l.Allow("192.168.1.1"))
	assert.True(t, l.Allow("192.168.1.1"))
}

func TestAllow_ExceedsRate(t *testing.T) {
	l := New(2, time.Second)
	defer l.Stop()

	// First 2 allowed
	assert.True(t, l.Allow("10.0.0.1"))
	assert.True(t, l.Allow("10.0.0.1"))

	// Third should be denied
	assert.False(t, l.Allow("10.0.0.1"))
	assert.False(t, l.Allow("10.0.0.1"))
}

func TestAllowDifferentIPs(t *testing.T) {
	l := New(1, time.Second)
	defer l.Stop()

	// Each IP gets its own bucket
	assert.True(t, l.Allow("192.168.1.1"))
	assert.True(t, l.Allow("192.168.1.2"))
	assert.True(t, l.Allow("192.168.1.3"))

	// First IP is now exhausted
	assert.False(t, l.Allow("192.168.1.1"))

	// Other IPs are also exhausted
	assert.False(t, l.Allow("192.168.1.2"))
	assert.False(t, l.Allow("192.168.1.3"))
}

func TestWindowReset(t *testing.T) {
	l := New(1, 50*time.Millisecond)
	defer l.Stop()

	// Use up the one allowed request
	assert.True(t, l.Allow("10.0.0.1"))
	assert.False(t, l.Allow("10.0.0.1"))

	// Wait for the window to elapse
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again after window reset
	assert.True(t, l.Allow("10.0.0.1"))
}

func TestStop(t *testing.T) {
	l := New(10, time.Second)
	// Should not panic on stop
	l.Stop()
}
