package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	cfg := defaults()

	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, 25, cfg.Database.MaxConnections)
	assert.Equal(t, true, cfg.Auth.AllowRegistration)
	assert.Equal(t, 30, cfg.Agent.MaxIterations)
	assert.Equal(t, 3, cfg.Agent.MaxParallelTools)
	assert.Equal(t, true, cfg.Agent.AutoReview)
	assert.Equal(t, "tools", cfg.Tools.Dir)
	assert.Equal(t, "roles", cfg.Roles.Dir)
	assert.Equal(t, "skills", cfg.Skills.Dir)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoadFromFile(t *testing.T) {
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "config.yaml")

	content := `
server:
  host: "127.0.0.1"
  port: 9090
agent:
  max_iterations: 50
  auto_review: false
logging:
  level: "debug"
`
	err := os.WriteFile(cfgFile, []byte(content), 0644)
	require.NoError(t, err)

	t.Setenv("CONFIG_PATH", cfgFile)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, 50, cfg.Agent.MaxIterations)
	assert.False(t, cfg.Agent.AutoReview)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestEnvOverrides(t *testing.T) {
	cfg := defaults()

	t.Setenv("DATABASE_URL", "postgres://test:test@localhost/test")
	t.Setenv("REDIS_URL", "redis://localhost:6380")
	t.Setenv("JWT_SECRET", "test-secret-123")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("LOG_LEVEL", "debug")

	applyEnvOverrides(cfg)

	assert.Equal(t, "postgres://test:test@localhost/test", cfg.Database.URL)
	assert.Equal(t, "redis://localhost:6380", cfg.Redis.URL)
	assert.Equal(t, "test-secret-123", cfg.Auth.JWTSecret)
	assert.Equal(t, "sk-ant-test", cfg.Providers.Anthropic.APIKey)
	assert.Equal(t, "sk-test", cfg.Providers.OpenAI.APIKey)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestAgentConfigDefaults(t *testing.T) {
	cfg := AgentConfig{
		MaxIterations:    10,
		MaxParallelTools: 5,
		ThinkingBudget:   4096,
		AutoReview:       true,
	}

	assert.Equal(t, 10, cfg.MaxIterations)
	assert.Equal(t, 5, cfg.MaxParallelTools)
	assert.Equal(t, 4096, cfg.ThinkingBudget)
	assert.True(t, cfg.AutoReview)
}

func TestServerConfigTimeouts(t *testing.T) {
	cfg := ServerConfig{
		Host:         "localhost",
		Port:         8080,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 120*time.Second, cfg.WriteTimeout)
}

func TestStorageConfig(t *testing.T) {
	cfg := StorageConfig{
		Type: "s3",
		S3: S3Config{
			Endpoint:  "http://localhost:9000",
			Bucket:    "test-bucket",
			AccessKey: "access",
			SecretKey: "secret",
		},
	}

	assert.Equal(t, "s3", cfg.Type)
	assert.Equal(t, "test-bucket", cfg.S3.Bucket)
}
