package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// SmartRouter implements intelligent provider selection based on multiple criteria.
type SmartRouter struct {
	router        *Router
	healthMonitor *HealthMonitor
	rateLimiter   *RateLimiter
	costTracker   *CostTracker

	// Routing strategies
	strategy       RoutingStrategy
	fallbackChain  []string
	modelMappings  map[string][]string // model name -> provider preference list
	budgetLimit    float64             // USD budget limit
	latencyTarget  time.Duration       // target latency

	mu sync.RWMutex
}

// RoutingStrategy determines how providers are selected.
type RoutingStrategy int

const (
	// StrategyFallback uses the fallback chain in order.
	StrategyFallback RoutingStrategy = iota
	// StrategyRoundRobin rotates between healthy providers.
	StrategyRoundRobin
	// StrategyLeastCost selects the cheapest provider.
	StrategyLeastCost
	// StrategyLowestLatency selects the provider with lowest latency.
	StrategyLowestLatency
	// StrategyRandom randomly selects from healthy providers.
	StrategyRandom
	// StrategyCapability selects based on model capabilities.
	StrategyCapability
)

func (s RoutingStrategy) String() string {
	switch s {
	case StrategyFallback:
		return "fallback"
	case StrategyRoundRobin:
		return "round_robin"
	case StrategyLeastCost:
		return "least_cost"
	case StrategyLowestLatency:
		return "lowest_latency"
	case StrategyRandom:
		return "random"
	case StrategyCapability:
		return "capability"
	default:
		return "unknown"
	}
}

// NewSmartRouter creates a new smart router with the given components.
func NewSmartRouter(
	router *Router,
	healthMonitor *HealthMonitor,
	rateLimiter *RateLimiter,
	costTracker *CostTracker,
) *SmartRouter {
	return &SmartRouter{
		router:        router,
		healthMonitor: healthMonitor,
		rateLimiter:   rateLimiter,
		costTracker:   costTracker,
		strategy:      StrategyFallback,
		modelMappings: make(map[string][]string),
		latencyTarget: 5 * time.Second,
	}
}

// SetStrategy sets the routing strategy.
func (sr *SmartRouter) SetStrategy(strategy RoutingStrategy) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.strategy = strategy
	slog.Info("routing strategy changed", "strategy", strategy.String())
}

// SetModelMapping sets the preferred provider list for a specific model.
func (sr *SmartRouter) SetModelMapping(model string, providers []string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Normalize model name
	model = strings.ToLower(model)
	sr.modelMappings[model] = providers
	slog.Info("model mapping set", "model", model, "providers", providers)
}

// SetBudgetLimit sets the maximum budget in USD.
func (sr *SmartRouter) SetBudgetLimit(limit float64) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.budgetLimit = limit
}

// SetLatencyTarget sets the target latency.
func (sr *SmartRouter) SetLatencyTarget(target time.Duration) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.latencyTarget = target
}

// ChatCompletion performs a chat completion using the smart router.
func (sr *SmartRouter) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	providers := sr.selectProviders(req.Model)

	var lastErr error
	for _, name := range providers {
		// Check rate limiting
		if sr.rateLimiter != nil {
			if err := sr.rateLimiter.Wait(ctx, name); err != nil {
				continue
			}
		}

		// Check circuit breaker
		if sr.healthMonitor != nil && sr.healthMonitor.IsCircuitOpen(name) {
			slog.Debug("skipping provider, circuit open", "provider", name)
			continue
		}

		// Get provider
		p, ok := sr.router.Get(name)
		if !ok {
			continue
		}

		// Execute request
		start := time.Now()
		resp, err := p.ChatCompletion(ctx, req)
		latency := time.Since(start)

		if err != nil {
			lastErr = err
			if sr.costTracker != nil {
				sr.costTracker.RecordFailure(name)
			}
			slog.Warn("provider request failed", "provider", name, "error", err, "latency", latency)
			continue
		}

		// Success - record metrics
		if sr.costTracker != nil && resp != nil {
			sr.costTracker.RecordUsage(name, resp.Usage.InputTokens, resp.Usage.OutputTokens)
		}

		slog.Debug("provider request succeeded",
			"provider", name,
			"latency", latency,
			"model", resp.Model,
		)

		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, errors.New("no providers available")
}

// StreamChatCompletion performs a streaming chat completion using the smart router.
func (sr *SmartRouter) StreamChatCompletion(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	providers := sr.selectProviders(req.Model)

	for _, name := range providers {
		// Check rate limiting
		if sr.rateLimiter != nil {
			if err := sr.rateLimiter.Wait(ctx, name); err != nil {
				continue
			}
		}

		// Check circuit breaker
		if sr.healthMonitor != nil && sr.healthMonitor.IsCircuitOpen(name) {
			continue
		}

		// Get provider
		p, ok := sr.router.Get(name)
		if !ok {
			continue
		}

		ch, err := p.StreamChatCompletion(ctx, req)
		if err != nil {
			slog.Warn("provider stream request failed", "provider", name, "error", err)
			continue
		}

		// Wrap the channel to track usage
		return sr.wrapStreamChannel(ch, name), nil
	}

	return nil, errors.New("no providers available for streaming")
}

// selectProviders returns the list of providers to try based on the current strategy.
func (sr *SmartRouter) selectProviders(model string) []string {
	sr.mu.RLock()
	strategy := sr.strategy
	model = strings.ToLower(model)
	mappings := sr.modelMappings[model]
	sr.mu.RUnlock()

	// If we have a specific mapping for this model, use it
	if len(mappings) > 0 {
		return sr.filterHealthy(mappings)
	}

	switch strategy {
	case StrategyRoundRobin:
		return sr.selectRoundRobin()
	case StrategyLeastCost:
		return sr.selectLeastCost()
	case StrategyLowestLatency:
		return sr.selectLowestLatency()
	case StrategyRandom:
		return sr.selectRandom()
	case StrategyCapability:
		return sr.selectByCapability(model)
	default:
		// StrategyFallback - use the router's fallback chain
		return sr.router.GetFallbackChain()
	}
}

// filterHealthy returns only healthy providers from the list.
func (sr *SmartRouter) filterHealthy(providers []string) []string {
	var healthy []string
	for _, name := range providers {
		if sr.healthMonitor == nil {
			healthy = append(healthy, name)
			continue
		}

		h, ok := sr.healthMonitor.GetHealth(name)
		if !ok {
			healthy = append(healthy, name)
			continue
		}

		if h.Status == HealthHealthy || h.Status == HealthDegraded {
			healthy = append(healthy, name)
		}
	}
	return healthy
}

var roundRobinIndex uint32

func (sr *SmartRouter) selectRoundRobin() []string {
	providers := sr.healthMonitor.GetHealthyProviders()
	if len(providers) == 0 {
		return sr.router.GetFallbackChain()
	}

	// Get next index atomically
	idx := int(rand.Uint32()) % len(providers)

	// Rotate the list starting from idx
	result := make([]string, len(providers))
	for i := 0; i < len(providers); i++ {
		result[i] = providers[(idx+i)%len(providers)]
	}
	return result
}

func (sr *SmartRouter) selectLeastCost() []string {
	providers := sr.healthMonitor.GetHealthyProviders()
	if len(providers) == 0 {
		return sr.router.GetFallbackChain()
	}

	// Sort by estimated cost per 1K tokens
	type providerCost struct {
		name string
		cost float64
	}

	var costs []providerCost
	for _, name := range providers {
		if c, ok := sr.costTracker.GetCost(name); ok {
			avgCost := (c.PricePer1KInput + c.PricePer1KOutput) / 2
			costs = append(costs, providerCost{name, avgCost})
		} else {
			// Unknown cost, assume high to prioritize known providers
			costs = append(costs, providerCost{name, 999999})
		}
	}

	// Sort by cost (cheapest first) - simple bubble sort
	for i := 0; i < len(costs); i++ {
		for j := i + 1; j < len(costs); j++ {
			if costs[j].cost < costs[i].cost {
				costs[i], costs[j] = costs[j], costs[i]
			}
		}
	}

	result := make([]string, len(costs))
	for i, pc := range costs {
		result[i] = pc.name
	}
	return result
}

func (sr *SmartRouter) selectLowestLatency() []string {
	providers := sr.healthMonitor.GetHealthyProviders()
	if len(providers) == 0 {
		return sr.router.GetFallbackChain()
	}

	// Sort by average latency
	type providerLatency struct {
		name    string
		latency time.Duration
	}

	var latencies []providerLatency
	for _, name := range providers {
		if h, ok := sr.healthMonitor.GetHealth(name); ok {
			latencies = append(latencies, providerLatency{name, h.AvgLatency})
		} else {
			latencies = append(latencies, providerLatency{name, time.Hour})
		}
	}

	// Sort by latency (lowest first)
	for i := 0; i < len(latencies); i++ {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[j].latency < latencies[i].latency {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}

	result := make([]string, len(latencies))
	for i, pl := range latencies {
		result[i] = pl.name
	}
	return result
}

func (sr *SmartRouter) selectRandom() []string {
	providers := sr.healthMonitor.GetHealthyProviders()
	if len(providers) == 0 {
		return sr.router.GetFallbackChain()
	}

	// Shuffle the providers
	rand.Shuffle(len(providers), func(i, j int) {
		providers[i], providers[j] = providers[j], providers[i]
	})
	return providers
}

func (sr *SmartRouter) selectByCapability(model string) []string {
	// Map of models to their typical context windows and best providers
	capabilityMap := map[string][]string{
		"claude":      {"anthropic", "openrouter"},
		"gpt-4":       {"openai", "azure", "openrouter"},
		"gpt-3.5":     {"openai", "groq", "together"},
		"llama":       {"together", "groq", "fireworks"},
		"gemini":      {"gemini", "openrouter"},
		"mistral":     {"mistral", "openrouter"},
		"deepseek":    {"deepseek", "openrouter"},
		"glm":         {"glm"},
		"command":     {"cohere"},
	}

	// Find matching capability
	modelLower := strings.ToLower(model)
	for prefix, providers := range capabilityMap {
		if strings.Contains(modelLower, prefix) {
			return sr.filterHealthy(providers)
		}
	}

	// Default to fallback chain
	return sr.router.GetFallbackChain()
}

// wrapStreamChannel wraps a stream channel to track usage.
func (sr *SmartRouter) wrapStreamChannel(ch <-chan StreamEvent, providerName string) <-chan StreamEvent {
	wrapped := make(chan StreamEvent, 100)

	go func() {
		defer close(wrapped)

		for event := range ch {
			if event.Type == "done" && event.Usage != nil {
				if sr.costTracker != nil {
					sr.costTracker.RecordUsage(providerName, event.Usage.InputTokens, event.Usage.OutputTokens)
				}
			}
			wrapped <- event
		}
	}()

	return wrapped
}

// GetStats returns router statistics.
func (sr *SmartRouter) GetStats() map[string]interface{} {
	sr.mu.RLock()
	strategy := sr.strategy
	budgetLimit := sr.budgetLimit
	sr.mu.RUnlock()

	stats := map[string]interface{}{
		"strategy":      strategy.String(),
		"budget_limit":  budgetLimit,
		"total_cost":    sr.costTracker.GetTotalCost(),
	}

	if sr.healthMonitor != nil {
		healthStats := make(map[string]interface{})
		for name, health := range sr.healthMonitor.GetAllHealth() {
			health.mu.RLock()
			healthStats[name] = map[string]interface{}{
				"status":       health.Status.String(),
				"latency":      health.AvgLatency,
				"success":      health.SuccessCount,
				"failures":     health.FailureCount,
				"circuit_open": health.CircuitOpen,
			}
			health.mu.RUnlock()
		}
		stats["health"] = healthStats
	}

	return stats
}
