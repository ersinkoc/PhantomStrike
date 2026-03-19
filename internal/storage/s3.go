package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

// S3Storage implements Provider for S3-compatible object storage (AWS S3, MinIO).
type S3Storage struct {
	client *minio.Client
	bucket string
}

// NewS3Storage creates a new S3-compatible storage provider using the MinIO SDK.
func NewS3Storage(cfg config.S3Config) (*S3Storage, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("S3 endpoint is required")
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("S3 bucket is required")
	}

	// Parse endpoint: strip scheme to get host for minio client and detect TLS.
	endpoint := cfg.Endpoint
	useSSL := strings.HasPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("creating S3 client: %w", err)
	}

	// Ensure the bucket exists.
	ctx := context.Background()
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("checking bucket existence: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("creating bucket %s: %w", cfg.Bucket, err)
		}
		slog.Info("created S3 bucket", "bucket", cfg.Bucket)
	}

	slog.Info("S3 storage configured",
		"endpoint", cfg.Endpoint,
		"bucket", cfg.Bucket,
	)

	return &S3Storage{
		client: client,
		bucket: cfg.Bucket,
	}, nil
}

// Save stores data in S3 at the given path.
func (s *S3Storage) Save(ctx context.Context, path string, data []byte) (string, error) {
	reader := bytes.NewReader(data)
	_, err := s.client.PutObject(ctx, s.bucket, path, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: GetMimeType(path),
	})
	if err != nil {
		return "", fmt.Errorf("S3 PutObject %s: %w", path, err)
	}
	return fmt.Sprintf("s3://%s/%s", s.bucket, path), nil
}

// Load retrieves the full contents of an object from S3.
func (s *S3Storage) Load(ctx context.Context, path string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, path, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("S3 GetObject %s: %w", path, err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("reading S3 object %s: %w", path, err)
	}
	return data, nil
}

// Delete removes an object from S3.
func (s *S3Storage) Delete(ctx context.Context, path string) error {
	err := s.client.RemoveObject(ctx, s.bucket, path, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("S3 RemoveObject %s: %w", path, err)
	}
	return nil
}

// Exists checks whether an object exists in S3.
func (s *S3Storage) Exists(ctx context.Context, path string) (bool, error) {
	_, err := s.client.StatObject(ctx, s.bucket, path, minio.StatObjectOptions{})
	if err != nil {
		errResp := minio.ToErrorResponse(err)
		if errResp.Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("S3 StatObject %s: %w", path, err)
	}
	return true, nil
}

// Open returns a ReadCloser for streaming an S3 object.
func (s *S3Storage) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, path, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("S3 GetObject %s: %w", path, err)
	}
	return obj, nil
}
