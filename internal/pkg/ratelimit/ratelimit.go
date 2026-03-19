package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter provides token-bucket rate limiting per IP address.
type Limiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // requests per window
	window   time.Duration
	done     chan struct{}
}

type visitor struct {
	tokens    int
	lastReset time.Time
}

// New creates a new rate limiter that allows `rate` requests per `window` duration.
// It starts a background goroutine to clean up stale visitor entries.
func New(rate int, window time.Duration) *Limiter {
	l := &Limiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		done:     make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// Allow checks whether the given IP is allowed to make a request.
// Returns true if the request is within the rate limit, false otherwise.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	v, exists := l.visitors[ip]
	if !exists {
		l.visitors[ip] = &visitor{
			tokens:    l.rate - 1,
			lastReset: now,
		}
		return true
	}

	// Reset tokens if the window has elapsed
	if now.Sub(v.lastReset) >= l.window {
		v.tokens = l.rate - 1
		v.lastReset = now
		return true
	}

	if v.tokens > 0 {
		v.tokens--
		return true
	}

	return false
}

// Middleware returns an HTTP middleware that rate limits requests by client IP.
// When rate limited, it responds with 429 Too Many Requests and a Retry-After header.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)

		if !l.Allow(ip) {
			retryAfter := int(l.window.Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Stop halts the background cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.done)
}

// cleanup periodically removes visitors whose window has expired.
func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()

	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			for ip, v := range l.visitors {
				if now.Sub(v.lastReset) > 2*l.window {
					delete(l.visitors, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

// realIP extracts the client IP from common proxy headers.
func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.SplitN(forwarded, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
