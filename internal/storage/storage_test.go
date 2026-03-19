package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalStorageSaveAndLoad(t *testing.T) {
	tmp := t.TempDir()
	ls, err := NewLocalStorage(tmp)
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("hello world")

	path, err := ls.Save(ctx, "test/file.txt", data)
	require.NoError(t, err)
	assert.NotEmpty(t, path)

	loaded, err := ls.Load(ctx, "test/file.txt")
	require.NoError(t, err)
	assert.Equal(t, data, loaded)
}

func TestLocalStorageExists(t *testing.T) {
	tmp := t.TempDir()
	ls, err := NewLocalStorage(tmp)
	require.NoError(t, err)

	ctx := context.Background()

	exists, err := ls.Exists(ctx, "nonexistent.txt")
	require.NoError(t, err)
	assert.False(t, exists)

	ls.Save(ctx, "exists.txt", []byte("data"))
	exists, err = ls.Exists(ctx, "exists.txt")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestLocalStorageDelete(t *testing.T) {
	tmp := t.TempDir()
	ls, err := NewLocalStorage(tmp)
	require.NoError(t, err)

	ctx := context.Background()
	ls.Save(ctx, "del.txt", []byte("data"))

	err = ls.Delete(ctx, "del.txt")
	assert.NoError(t, err)

	exists, _ := ls.Exists(ctx, "del.txt")
	assert.False(t, exists)
}

func TestLocalStorageOpen(t *testing.T) {
	tmp := t.TempDir()
	ls, err := NewLocalStorage(tmp)
	require.NoError(t, err)

	ctx := context.Background()
	ls.Save(ctx, "open.txt", []byte("stream data"))

	rc, err := ls.Open(ctx, "open.txt")
	require.NoError(t, err)
	defer rc.Close()

	buf := make([]byte, 100)
	n, _ := rc.Read(buf)
	assert.Equal(t, "stream data", string(buf[:n]))
}

func TestLocalStorageSubdirectories(t *testing.T) {
	tmp := t.TempDir()
	_, err := NewLocalStorage(tmp)
	require.NoError(t, err)

	// Check subdirectories were created
	for _, sub := range []string{"reports", "artifacts", "uploads"} {
		_, err := os.Stat(filepath.Join(tmp, sub))
		assert.NoError(t, err, "subdirectory %s should exist", sub)
	}
}

func TestGeneratePath(t *testing.T) {
	path := GeneratePath("reports", "abc-123", "pdf")
	assert.Contains(t, path, "reports")
	assert.Contains(t, path, "abc-123")
	assert.Contains(t, path, ".pdf")
}

func TestGetMimeType(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"report.pdf", "application/pdf"},
		{"data.json", "application/json"},
		{"readme.md", "text/markdown"},
		{"page.html", "text/html"},
		{"file.unknown", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetMimeType(tt.filename))
		})
	}
}
