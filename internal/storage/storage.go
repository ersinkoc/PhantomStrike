// Package storage provides file storage abstraction for reports and artifacts.
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Provider defines the interface for file storage backends.
type Provider interface {
	// Save stores data at the given path and returns the full storage path.
	Save(ctx context.Context, path string, data []byte) (string, error)
	// Load retrieves data from the given path.
	Load(ctx context.Context, path string) ([]byte, error)
	// Delete removes the file at the given path.
	Delete(ctx context.Context, path string) error
	// Exists checks if a file exists at the given path.
	Exists(ctx context.Context, path string) (bool, error)
	// Open returns a ReadCloser for streaming large files.
	Open(ctx context.Context, path string) (io.ReadCloser, error)
}

// LocalStorage implements Provider for local filesystem storage.
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a new local filesystem storage provider.
func NewLocalStorage(basePath string) (*LocalStorage, error) {
	if basePath == "" {
		basePath = "./storage"
	}

	// Ensure base path exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("creating storage directory: %w", err)
	}

	// Create subdirectories
	for _, sub := range []string{"reports", "artifacts", "uploads"} {
		if err := os.MkdirAll(filepath.Join(basePath, sub), 0755); err != nil {
			return nil, fmt.Errorf("creating %s directory: %w", sub, err)
		}
	}

	return &LocalStorage{basePath: basePath}, nil
}

// Save stores data to the local filesystem.
func (l *LocalStorage) Save(ctx context.Context, path string, data []byte) (string, error) {
	fullPath := filepath.Join(l.basePath, path)

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating directory: %w", err)
	}

	// Write file atomically using temp file
	tempPath := fullPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return "", fmt.Errorf("writing temp file: %w", err)
	}

	if err := os.Rename(tempPath, fullPath); err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("renaming file: %w", err)
	}

	return fullPath, nil
}

// Load reads data from the local filesystem.
func (l *LocalStorage) Load(ctx context.Context, path string) ([]byte, error) {
	fullPath := filepath.Join(l.basePath, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return data, nil
}

// Delete removes a file from the local filesystem.
func (l *LocalStorage) Delete(ctx context.Context, path string) error {
	fullPath := filepath.Join(l.basePath, path)
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting file: %w", err)
	}
	return nil
}

// Exists checks if a file exists.
func (l *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	fullPath := filepath.Join(l.basePath, path)
	_, err := os.Stat(fullPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Open returns a ReadCloser for streaming.
func (l *LocalStorage) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath := filepath.Join(l.basePath, path)
	f, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return f, nil
}

// GeneratePath generates a unique storage path for a file.
func GeneratePath(category, id, extension string) string {
	timestamp := time.Now().Unix()
	return filepath.Join(category, fmt.Sprintf("%s_%d.%s", id, timestamp, extension))
}

// GetMimeType returns the MIME type for a given file extension.
func GetMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".json":
		return "application/json"
	case ".md", ".markdown":
		return "text/markdown"
	case ".html", ".htm":
		return "text/html"
	case ".txt":
		return "text/plain"
	case ".xml":
		return "application/xml"
	case ".csv":
		return "text/csv"
	default:
		return "application/octet-stream"
	}
}
