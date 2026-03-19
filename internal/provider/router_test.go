package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testProvider is a minimal Provider implementation for testing.
type testProvider struct {
	name     string
	response *ChatResponse
	err      error
}

func (p *testProvider) ChatCompletion(_ context.Context, _ ChatRequest) (*ChatResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.response, nil
}

func (p *testProvider) StreamChatCompletion(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	ch := make(chan StreamEvent)
	close(ch)
	return ch, nil
}

func (p *testProvider) Embedding(_ context.Context, _ []string) ([][]float64, error) { return nil, nil }
func (p *testProvider) Models(_ context.Context) ([]Model, error)                     { return nil, nil }
func (p *testProvider) Name() string                                                  { return p.name }
func (p *testProvider) SupportsToolCalling() bool                                     { return true }
func (p *testProvider) MaxContextWindow(_ string) int                                 { return 4096 }

func TestRouterRegisterAndGet(t *testing.T) {
	r := NewRouter("primary", []string{"primary"})

	p := &testProvider{name: "primary"}
	r.Register("primary", p)

	got, ok := r.Get("primary")
	assert.True(t, ok)
	assert.Equal(t, "primary", got.Name())

	_, ok = r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRouterDefault(t *testing.T) {
	r := NewRouter("main", []string{"main"})
	r.Register("main", &testProvider{name: "main"})

	p, err := r.Default()
	require.NoError(t, err)
	assert.Equal(t, "main", p.Name())
}

func TestRouterDefaultNotConfigured(t *testing.T) {
	r := NewRouter("missing", nil)
	_, err := r.Default()
	assert.Error(t, err)
}

func TestRouterFallbackChain(t *testing.T) {
	r := NewRouter("p1", []string{"p1", "p2", "p3"})

	// p1 fails, p2 succeeds
	r.Register("p1", &testProvider{name: "p1", err: errors.New("down")})
	r.Register("p2", &testProvider{name: "p2", response: &ChatResponse{Content: "from p2"}})
	r.Register("p3", &testProvider{name: "p3", response: &ChatResponse{Content: "from p3"}})

	resp, err := r.ChatCompletion(context.Background(), ChatRequest{})
	require.NoError(t, err)
	assert.Equal(t, "from p2", resp.Content)
}

func TestRouterAllProvidersFail(t *testing.T) {
	r := NewRouter("p1", []string{"p1"})
	r.Register("p1", &testProvider{name: "p1", err: errors.New("down")})

	_, err := r.ChatCompletion(context.Background(), ChatRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all providers failed")
}

func TestRouterNoProviders(t *testing.T) {
	r := NewRouter("empty", []string{})
	_, err := r.ChatCompletion(context.Background(), ChatRequest{})
	assert.Error(t, err)
}

func TestRouterGetRegisteredNames(t *testing.T) {
	r := NewRouter("a", nil)
	r.Register("a", &testProvider{name: "a"})
	r.Register("b", &testProvider{name: "b"})

	names := r.GetRegisteredNames()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "a")
	assert.Contains(t, names, "b")
}

func TestRouterSetFallbackChain(t *testing.T) {
	r := NewRouter("a", []string{"a"})
	assert.Equal(t, []string{"a"}, r.GetFallbackChain())

	r.SetFallbackChain([]string{"b", "c"})
	assert.Equal(t, []string{"b", "c"}, r.GetFallbackChain())
}
