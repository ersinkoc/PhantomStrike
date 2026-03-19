package provider

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ProviderHealth tracks the health status of a provider.
type ProviderHealth struct {
	Name           string
	Status         HealthStatus
	LastCheck      time.Time
	LastError      error
	SuccessCount   uint64
	FailureCount   uint64
	AvgLatency     time.Duration
	CircuitOpen    bool
	CircuitOpenAt  *time.Time
	ConsecutiveErr int
	mu             sync.RWMutex
}

// HealthStatus represents the health status of a provider.
type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthDegraded
	HealthUnhealthy
)

func (h HealthStatus) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthDegraded:
		return "degraded"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// HealthMonitor monitors the health of all registered providers.
type HealthMonitor struct {
	health    map[string]*ProviderHealth
	router    *Router
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	mu        sync.RWMutex
}

// NewHealthMonitor creates a new health monitor.
func NewHealthMonitor(router *Router, interval time.Duration) *HealthMonitor {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &HealthMonitor{
		health:   make(map[string]*ProviderHealth),
		router:   router,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins health monitoring in the background.
func (hm *HealthMonitor) Start() {
	hm.wg.Add(1)
	go hm.monitorLoop()
}

// Stop stops health monitoring.
func (hm *HealthMonitor) Stop() {
	close(hm.stopCh)
	hm.wg.Wait()
}

// GetHealth returns the health status for a provider.
func (hm *HealthMonitor) GetHealth(name string) (*ProviderHealth, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	h, ok := hm.health[name]
	return h, ok
}

// GetAllHealth returns health status for all providers.
func (hm *HealthMonitor) GetAllHealth() map[string]*ProviderHealth {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	result := make(map[string]*ProviderHealth, len(hm.health))
	for k, v := range hm.health {
		result[k] = v
	}
	return result
}

// RegisterProvider registers a provider for health monitoring.
func (hm *HealthMonitor) RegisterProvider(name string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.health[name] = &ProviderHealth{
		Name:   name,
		Status: HealthUnknown,
	}
}

func (hm *HealthMonitor) monitorLoop() {
	defer hm.wg.Done()

	// Initial check
	hm.checkAll()

	ticker := time.NewTicker(hm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hm.checkAll()
		case <-hm.stopCh:
			return
		}
	}
}

func (hm *HealthMonitor) checkAll() {
	providers := hm.router.GetAllProviders()

	var wg sync.WaitGroup
	for name, p := range providers {
		wg.Add(1)
		go func(n string, provider Provider) {
			defer wg.Done()
			hm.checkProvider(n, provider)
		}(name, p)
	}
	wg.Wait()
}

func (hm *HealthMonitor) checkProvider(name string, p Provider) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to get models as a health check
	_, err := p.Models(ctx)
	latency := time.Since(start)

	hm.mu.Lock()
	health, exists := hm.health[name]
	if !exists {
		health = &ProviderHealth{Name: name}
		hm.health[name] = health
	}
	hm.mu.Unlock()

	health.mu.Lock()
	defer health.mu.Unlock()

	health.LastCheck = time.Now()

	if err != nil {
		health.FailureCount++
		health.ConsecutiveErr++
		health.LastError = err

		// Update circuit breaker
		if health.ConsecutiveErr >= 5 {
			if !health.CircuitOpen {
				now := time.Now()
				health.CircuitOpenAt = &now
				health.CircuitOpen = true
				slog.Warn("circuit breaker opened", "provider", name)
			}
		}

		// Determine status
		switch {
		case health.CircuitOpen:
			health.Status = HealthUnhealthy
		case health.ConsecutiveErr >= 3:
			health.Status = HealthDegraded
		default:
			health.Status = HealthHealthy
		}
	} else {
		health.SuccessCount++
		health.ConsecutiveErr = 0

		// Close circuit if it was open
		if health.CircuitOpen {
			// Only close after some time has passed (cooldown)
			if health.CircuitOpenAt != nil && time.Since(*health.CircuitOpenAt) > 30*time.Second {
				health.CircuitOpen = false
				health.CircuitOpenAt = nil
				slog.Info("circuit breaker closed", "provider", name)
			}
		}

		// Update average latency
		if health.AvgLatency == 0 {
			health.AvgLatency = latency
		} else {
			health.AvgLatency = (health.AvgLatency*9 + latency) / 10
		}

		health.Status = HealthHealthy
		health.LastError = nil
	}
}

// IsCircuitOpen checks if the circuit breaker is open for a provider.
func (hm *HealthMonitor) IsCircuitOpen(name string) bool {
	hm.mu.RLock()
	health, ok := hm.health[name]
	hm.mu.RUnlock()
	if !ok {
		return false
	}

	health.mu.RLock()
	defer health.mu.RUnlock()
	return health.CircuitOpen
}

// GetHealthyProviders returns names of all healthy providers.
func (hm *HealthMonitor) GetHealthyProviders() []string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var healthy []string
	for name, health := range hm.health {
		health.mu.RLock()
		if health.Status == HealthHealthy && !health.CircuitOpen {
			healthy = append(healthy, name)
		}
		health.mu.RUnlock()
	}
	return healthy
}

// --- Rate Limiting ---

// RateLimiter implements token bucket rate limiting per provider.
type RateLimiter struct {
	limits   map[string]*tokenBucket
	mu       sync.RWMutex
}

// tokenBucket represents a token bucket for rate limiting.
type tokenBucket struct {
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[string]*tokenBucket),
	}
}

// SetLimit configures rate limiting for a provider.
// rps: requests per second, burst: maximum burst size.
func (rl *RateLimiter) SetLimit(provider string, rps float64, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.limits[provider] = &tokenBucket{
		tokens:     float64(burst),
		capacity:   float64(burst),
		refillRate: rps,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed for the given provider.
func (rl *RateLimiter) Allow(provider string) bool {
	rl.mu.RLock()
	bucket, exists := rl.limits[provider]
	rl.mu.RUnlock()

	if !exists {
		return true // No limit configured
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens = min(bucket.capacity, bucket.tokens+elapsed*bucket.refillRate)
	bucket.lastRefill = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}

// Wait blocks until a request is allowed or context is cancelled.
func (rl *RateLimiter) Wait(ctx context.Context, provider string) error {
	for {
		if rl.Allow(provider) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
			// Try again
		}
	}
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// --- Cost Tracking ---

// CostTracker tracks usage costs per provider.
type CostTracker struct {
	costs map[string]*ProviderCost
	mu    sync.RWMutex
}

// ProviderCost tracks cost information for a provider.
type ProviderCost struct {
	ProviderName     string
	InputTokens      uint64
	OutputTokens     uint64
	TotalRequests    uint64
	FailedRequests   uint64
	EstimatedCostUSD float64
	PricePer1KInput  float64 // USD per 1K input tokens
	PricePer1KOutput float64 // USD per 1K output tokens
	mu               sync.RWMutex
}

// NewCostTracker creates a new cost tracker.
func NewCostTracker() *CostTracker {
	ct := &CostTracker{
		costs: make(map[string]*ProviderCost),
	}
	// Initialize with default pricing
	ct.setDefaultPricing()
	return ct
}

func (ct *CostTracker) setDefaultPricing() {
	// Default pricing per 1K tokens (approximate, update as needed)
	defaults := map[string]struct {
		input  float64
		output float64
	}{
		"anthropic": {0.003, 0.015},    // Claude 3.5 Sonnet
		"openai":    {0.005, 0.015},    // GPT-4o
		"deepseek":  {0.00014, 0.00028}, // DeepSeek V3
		"glm":       {0.001, 0.002},    // GLM-4
		"together":  {0.0008, 0.0008},  // Llama 3.3 70B
		"mistral":   {0.002, 0.006},    // Mistral Large
		"cohere":    {0.002, 0.006},    // Command R+
		"groq":      {0.00027, 0.00027}, // Llama 3.1 70B
		"gemini":    {0.0005, 0.0015},  // Gemini 1.5 Pro
	}

	for name, prices := range defaults {
		ct.costs[name] = &ProviderCost{
			ProviderName:     name,
			PricePer1KInput:  prices.input,
			PricePer1KOutput: prices.output,
		}
	}
}

// SetPricing configures pricing for a provider.
func (ct *CostTracker) SetPricing(provider string, pricePer1KInput, pricePer1KOutput float64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if cost, exists := ct.costs[provider]; exists {
		cost.mu.Lock()
		cost.PricePer1KInput = pricePer1KInput
		cost.PricePer1KOutput = pricePer1KOutput
		cost.mu.Unlock()
	} else {
		ct.costs[provider] = &ProviderCost{
			ProviderName:     provider,
			PricePer1KInput:  pricePer1KInput,
			PricePer1KOutput: pricePer1KOutput,
		}
	}
}

// RecordUsage records token usage for cost calculation.
func (ct *CostTracker) RecordUsage(provider string, inputTokens, outputTokens int) {
	ct.mu.RLock()
	cost, exists := ct.costs[provider]
	ct.mu.RUnlock()

	if !exists {
		// Create with zero pricing
		ct.mu.Lock()
		cost = &ProviderCost{
			ProviderName: provider,
		}
		ct.costs[provider] = cost
		ct.mu.Unlock()
	}

	cost.mu.Lock()
	defer cost.mu.Unlock()

	cost.InputTokens += uint64(inputTokens)
	cost.OutputTokens += uint64(outputTokens)
	cost.TotalRequests++

	// Calculate cost
	inputCost := float64(inputTokens) / 1000 * cost.PricePer1KInput
	outputCost := float64(outputTokens) / 1000 * cost.PricePer1KOutput
	cost.EstimatedCostUSD += inputCost + outputCost
}

// RecordFailure records a failed request.
func (ct *CostTracker) RecordFailure(provider string) {
	ct.mu.RLock()
	cost, exists := ct.costs[provider]
	ct.mu.RUnlock()

	if !exists {
		return
	}

	cost.mu.Lock()
	cost.FailedRequests++
	cost.mu.Unlock()
}

// GetCost returns cost information for a provider.
func (ct *CostTracker) GetCost(provider string) (*ProviderCost, bool) {
	ct.mu.RLock()
	cost, exists := ct.costs[provider]
	ct.mu.RUnlock()

	if !exists {
		return nil, false
	}

	cost.mu.RLock()
	defer cost.mu.RUnlock()

	// Return a copy
	return &ProviderCost{
		ProviderName:     cost.ProviderName,
		InputTokens:      cost.InputTokens,
		OutputTokens:     cost.OutputTokens,
		TotalRequests:    cost.TotalRequests,
		FailedRequests:   cost.FailedRequests,
		EstimatedCostUSD: cost.EstimatedCostUSD,
		PricePer1KInput:  cost.PricePer1KInput,
		PricePer1KOutput: cost.PricePer1KOutput,
	}, true
}

// GetAllCosts returns cost information for all providers.
func (ct *CostTracker) GetAllCosts() map[string]*ProviderCost {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make(map[string]*ProviderCost, len(ct.costs))
	for name, cost := range ct.costs {
		cost.mu.RLock()
		result[name] = &ProviderCost{
			ProviderName:     cost.ProviderName,
			InputTokens:      cost.InputTokens,
			OutputTokens:     cost.OutputTokens,
			TotalRequests:    cost.TotalRequests,
			FailedRequests:   cost.FailedRequests,
			EstimatedCostUSD: cost.EstimatedCostUSD,
			PricePer1KInput:  cost.PricePer1KInput,
			PricePer1KOutput: cost.PricePer1KOutput,
		}
		cost.mu.RUnlock()
	}
	return result
}

// GetTotalCost returns the total estimated cost across all providers.
func (ct *CostTracker) GetTotalCost() float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var total float64
	for _, cost := range ct.costs {
		cost.mu.RLock()
		total += cost.EstimatedCostUSD
		cost.mu.RUnlock()
	}
	return total
}

// Reset resets all cost tracking data.
func (ct *CostTracker) Reset() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	for _, cost := range ct.costs {
		cost.mu.Lock()
		cost.InputTokens = 0
		cost.OutputTokens = 0
		cost.TotalRequests = 0
		cost.FailedRequests = 0
		cost.EstimatedCostUSD = 0
		cost.mu.Unlock()
	}
}
