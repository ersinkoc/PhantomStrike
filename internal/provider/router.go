package provider

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Router manages multiple providers with fallback chain support.
type Router struct {
	providers     map[string]Provider
	fallbackChain []string
	defaultName   string
	mu            sync.RWMutex
}

// NewRouter creates a new provider router.
func NewRouter(defaultName string, fallbackChain []string) *Router {
	return &Router{
		providers:     make(map[string]Provider),
		fallbackChain: fallbackChain,
		defaultName:   defaultName,
	}
}

// Register adds a provider to the router.
func (r *Router) Register(name string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = p
}

// Get returns a specific provider by name.
func (r *Router) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// Default returns the default provider.
func (r *Router) Default() (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[r.defaultName]
	if !ok {
		return nil, fmt.Errorf("default provider %q not configured", r.defaultName)
	}
	return p, nil
}

// ChatCompletion tries the fallback chain until one succeeds.
func (r *Router) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	r.mu.RLock()
	chain := r.fallbackChain
	providers := r.providers
	r.mu.RUnlock()

	var lastErr error
	for _, name := range chain {
		p, ok := providers[name]
		if !ok {
			continue
		}

		resp, err := p.ChatCompletion(ctx, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		slog.Warn("provider failed, trying next",
			"provider", name,
			"error", err,
		)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no providers configured")
}

// StreamChatCompletion tries the fallback chain for streaming.
func (r *Router) StreamChatCompletion(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	r.mu.RLock()
	chain := r.fallbackChain
	providers := r.providers
	r.mu.RUnlock()

	var lastErr error
	for _, name := range chain {
		p, ok := providers[name]
		if !ok {
			continue
		}

		ch, err := p.StreamChatCompletion(ctx, req)
		if err == nil {
			return ch, nil
		}

		lastErr = err
		slog.Warn("stream provider failed, trying next",
			"provider", name,
			"error", err,
		)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no providers configured")
}

// GetAllProviders returns all registered providers.
func (r *Router) GetAllProviders() map[string]Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]Provider, len(r.providers))
	for k, v := range r.providers {
		result[k] = v
	}
	return result
}

// GetFallbackChain returns the fallback chain.
func (r *Router) GetFallbackChain() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]string, len(r.fallbackChain))
	copy(result, r.fallbackChain)
	return result
}

// SetFallbackChain updates the fallback chain.
func (r *Router) SetFallbackChain(chain []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallbackChain = chain
}

// GetRegisteredNames returns all registered provider names.
func (r *Router) GetRegisteredNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
