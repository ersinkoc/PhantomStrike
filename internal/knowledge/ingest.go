package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IngestResult contains the outcome of a knowledge ingestion run.
type IngestResult struct {
	Total    int `json:"total"`
	Ingested int `json:"ingested"`
	Skipped  int `json:"skipped"`
	Errors   int `json:"errors"`
}

// IngestFromDirectory reads all .md files from the given directory tree and
// upserts them into the knowledge_items table. The parent directory name is
// used as the category and the filename (without extension) as the title.
// Files that already exist (matched by source_file) are updated.
func IngestFromDirectory(ctx context.Context, pool *pgxpool.Pool, dir string) (*IngestResult, error) {
	result := &IngestResult{}

	entries, err := findMarkdownFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("scanning knowledge directory %q: %w", dir, err)
	}
	result.Total = len(entries)

	for _, entry := range entries {
		content, err := os.ReadFile(entry.fullPath)
		if err != nil {
			slog.Warn("failed to read knowledge file", "path", entry.fullPath, "error", err)
			result.Errors++
			continue
		}

		trimmed := strings.TrimSpace(string(content))
		if trimmed == "" {
			result.Skipped++
			continue
		}

		tag, err := pool.Exec(ctx,
			`INSERT INTO knowledge_items (category, title, content, source_file)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (source_file) DO UPDATE
			   SET category = EXCLUDED.category,
			       title    = EXCLUDED.title,
			       content  = EXCLUDED.content,
			       updated_at = NOW()
			 WHERE knowledge_items.content IS DISTINCT FROM EXCLUDED.content`,
			entry.category, entry.title, trimmed, entry.sourceFile,
		)
		if err != nil {
			// If ON CONFLICT fails (no unique constraint), fall back to check-then-insert
			var count int
			checkErr := pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM knowledge_items WHERE source_file = $1`,
				entry.sourceFile,
			).Scan(&count)
			if checkErr == nil && count > 0 {
				// Already exists, update it
				_, updateErr := pool.Exec(ctx,
					`UPDATE knowledge_items SET category = $1, title = $2, content = $3, updated_at = NOW()
					 WHERE source_file = $4`,
					entry.category, entry.title, trimmed, entry.sourceFile,
				)
				if updateErr != nil {
					slog.Warn("failed to update knowledge item", "file", entry.sourceFile, "error", updateErr)
					result.Errors++
				} else {
					result.Skipped++ // updated existing
				}
			} else if checkErr == nil && count == 0 {
				// Does not exist, insert
				_, insertErr := pool.Exec(ctx,
					`INSERT INTO knowledge_items (category, title, content, source_file)
					 VALUES ($1, $2, $3, $4)`,
					entry.category, entry.title, trimmed, entry.sourceFile,
				)
				if insertErr != nil {
					slog.Warn("failed to insert knowledge item", "file", entry.sourceFile, "error", insertErr)
					result.Errors++
				} else {
					result.Ingested++
				}
			} else {
				slog.Warn("failed to check knowledge item", "file", entry.sourceFile, "error", err)
				result.Errors++
			}
			continue
		}

		if tag.RowsAffected() > 0 {
			result.Ingested++
		} else {
			result.Skipped++
		}
	}

	return result, nil
}

// IsEmpty returns true if the knowledge_items table has no rows.
func IsEmpty(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var count int
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM knowledge_items").Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// knowledgeEntry holds parsed file metadata.
type knowledgeEntry struct {
	fullPath   string
	sourceFile string // relative path like "knowledge/web/xss-testing.md"
	category   string // parent directory name, e.g. "web"
	title      string // filename without extension, e.g. "xss-testing"
}

// findMarkdownFiles walks the directory tree and returns all .md files.
func findMarkdownFiles(root string) ([]knowledgeEntry, error) {
	var entries []knowledgeEntry

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".md") {
			return nil
		}

		// Derive category from parent directory
		relPath, _ := filepath.Rel(root, path)
		relPath = filepath.ToSlash(relPath) // normalize to forward slashes
		dir := filepath.Dir(relPath)
		if dir == "." {
			dir = "general"
		}
		dir = filepath.ToSlash(dir) // ensure forward slashes

		// Title from filename
		title := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))

		// Source file is the relative path from project root style
		sourceFile := filepath.ToSlash(filepath.Join(filepath.Base(root), relPath))

		entries = append(entries, knowledgeEntry{
			fullPath:   path,
			sourceFile: sourceFile,
			category:   dir,
			title:      title,
		})
		return nil
	})

	return entries, err
}
