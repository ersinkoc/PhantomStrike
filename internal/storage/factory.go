package storage

import (
	"fmt"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

// NewProvider creates a storage provider based on configuration.
func NewProvider(cfg config.StorageConfig) (Provider, error) {
	switch cfg.Type {
	case "s3":
		return NewS3Storage(cfg.S3)
	case "local", "":
		return NewLocalStorage(cfg.Path)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.Type)
	}
}
