package cache

import (
	"context"
	"fmt"
)

// TokenBlacklist wraps a Cache to implement auth.TokenBlacklist.
type TokenBlacklist struct {
	cache *Cache
}

// NewTokenBlacklist creates a new TokenBlacklist backed by the given cache.
func NewTokenBlacklist(c *Cache) *TokenBlacklist {
	return &TokenBlacklist{cache: c}
}

// IsBlacklisted returns true if the token has been revoked.
func (b *TokenBlacklist) IsBlacklisted(ctx context.Context, token string) bool {
	key := fmt.Sprintf("blacklist:%s", token)
	return b.cache.Exists(ctx, key)
}
