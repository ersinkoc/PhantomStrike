package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

// S3Storage implements Provider for S3-compatible object storage (AWS S3, MinIO).
type S3Storage struct {
	endpoint  string
	bucket    string
	accessKey string
	secretKey string
	local     *LocalStorage // fallback for local operations
}

// NewS3Storage creates a new S3-compatible storage provider.
// For now this wraps local storage with S3-ready interface. Full S3 SDK
// integration can be added by replacing the method bodies with real
// aws-sdk-go-v2 calls when the dependency is desired.
func NewS3Storage(cfg config.S3Config) (*S3Storage, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("S3 endpoint is required")
	}

	slog.Info("S3 storage configured",
		"endpoint", cfg.Endpoint,
		"bucket", cfg.Bucket,
	)

	// Use local storage as underlying store until full S3 SDK is wired.
	// This keeps the binary lean without pulling in the AWS SDK dependency tree.
	local, err := NewLocalStorage("./storage")
	if err != nil {
		return nil, err
	}

	return &S3Storage{
		endpoint:  cfg.Endpoint,
		bucket:    cfg.Bucket,
		accessKey: cfg.AccessKey,
		secretKey: cfg.SecretKey,
		local:     local,
	}, nil
}

func (s *S3Storage) Save(ctx context.Context, path string, data []byte) (string, error) {
	// TODO: replace with real S3 PutObject when aws-sdk-go-v2 is added
	return s.local.Save(ctx, path, data)
}

func (s *S3Storage) Load(ctx context.Context, path string) ([]byte, error) {
	return s.local.Load(ctx, path)
}

func (s *S3Storage) Delete(ctx context.Context, path string) error {
	return s.local.Delete(ctx, path)
}

func (s *S3Storage) Exists(ctx context.Context, path string) (bool, error) {
	return s.local.Exists(ctx, path)
}

func (s *S3Storage) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	data, err := s.local.Load(ctx, path)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
