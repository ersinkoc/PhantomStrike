package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache wraps a Redis client with JSON serialization helpers.
type Cache struct {
	client *redis.Client
}

// New creates a new Redis-backed cache.
func New(redisURL string) (*Cache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	slog.Info("redis cache connected", "addr", opts.Addr)
	return &Cache{client: client}, nil
}

// Get retrieves a string value by key.
func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, key).Result()
}

// Set stores a string value with a TTL.
func (c *Cache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.client.Set(ctx, key, value, ttl).Err()
}

// Delete removes one or more keys.
func (c *Cache) Delete(ctx context.Context, keys ...string) error {
	return c.client.Del(ctx, keys...).Err()
}

// Exists checks whether a key exists.
func (c *Cache) Exists(ctx context.Context, key string) bool {
	n, err := c.client.Exists(ctx, key).Result()
	return err == nil && n > 0
}

// GetJSON retrieves a value and unmarshals it from JSON.
func (c *Cache) GetJSON(ctx context.Context, key string, dest any) error {
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// SetJSON marshals a value to JSON and stores it with a TTL.
func (c *Cache) SetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return c.client.Set(ctx, key, data, ttl).Err()
}

// Invalidate removes all keys matching a glob pattern (e.g. "tools:*").
func (c *Cache) Invalidate(ctx context.Context, pattern string) error {
	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}
	return nil
}

// IsNotFound returns true if the error indicates a cache miss.
func IsNotFound(err error) bool {
	return err == redis.Nil
}

// Close closes the Redis connection.
func (c *Cache) Close() error {
	return c.client.Close()
}
