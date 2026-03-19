package knowledge

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

func TestNewRetriever(t *testing.T) {
	cfg := config.RetrievalConfig{
		TopK:                10,
		SimilarityThreshold: 0.8,
		HybridWeight:        0.6,
	}

	r := NewRetriever(nil, cfg)
	require.NotNil(t, r)
	assert.Nil(t, r.pool)
	assert.Equal(t, 10, r.cfg.TopK)
	assert.Equal(t, 0.8, r.cfg.SimilarityThreshold)
	assert.Equal(t, 0.6, r.cfg.HybridWeight)
}

func TestSearchResultStruct(t *testing.T) {
	sr := SearchResult{
		ID:       "test-id",
		Title:    "SQL Injection",
		Content:  "SQL injection is a code injection technique...",
		Category: "web-vulnerabilities",
		Score:    0.95,
	}

	assert.Equal(t, "test-id", sr.ID)
	assert.Equal(t, "SQL Injection", sr.Title)
	assert.Contains(t, sr.Content, "SQL injection")
	assert.Equal(t, "web-vulnerabilities", sr.Category)
	assert.Equal(t, 0.95, sr.Score)
}

func TestSearchEmptyQuery(t *testing.T) {
	cfg := config.RetrievalConfig{TopK: 5}
	r := NewRetriever(nil, cfg)

	results, err := r.Search(context.Background(), "", "")
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "query is required")
}

func TestNewRetrieverDefaults(t *testing.T) {
	cfg := config.RetrievalConfig{}
	r := NewRetriever(nil, cfg)

	require.NotNil(t, r)
	assert.Equal(t, 0, r.cfg.TopK)
	assert.Equal(t, 0.0, r.cfg.SimilarityThreshold)
	assert.Equal(t, 0.0, r.cfg.HybridWeight)
}
