package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for PhantomStrike.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	Redis     RedisConfig     `yaml:"redis"`
	Storage   StorageConfig   `yaml:"storage"`
	Auth      AuthConfig      `yaml:"auth"`
	Providers ProvidersConfig `yaml:"providers"`
	MCP       MCPConfig       `yaml:"mcp"`
	Agent     AgentConfig     `yaml:"agent"`
	Tools     ToolsConfig     `yaml:"tools"`
	Roles     DirConfig       `yaml:"roles"`
	Skills    DirConfig       `yaml:"skills"`
	Knowledge KnowledgeConfig `yaml:"knowledge"`
	Scheduler SchedulerConfig `yaml:"scheduler"`
	Logging   LoggingConfig   `yaml:"logging"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

type ServerConfig struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	CORSOrigins    []string      `yaml:"cors_origins"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	MaxRequestBody string        `yaml:"max_request_body"`
}

type DatabaseConfig struct {
	URL            string `yaml:"url"`
	MaxConnections int    `yaml:"max_connections"`
	MigrationAuto  bool   `yaml:"migration_auto"`
}

type RedisConfig struct {
	URL string `yaml:"url"`
}

type StorageConfig struct {
	Type string   `yaml:"type"`
	Path string   `yaml:"path"`
	S3   S3Config `yaml:"s3"`
}

type S3Config struct {
	Endpoint  string `yaml:"endpoint"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
}

type AuthConfig struct {
	JWTSecret         string       `yaml:"jwt_secret"`
	TokenExpiry       time.Duration `yaml:"token_expiry"`
	RefreshExpiry     time.Duration `yaml:"refresh_expiry"`
	AllowRegistration bool         `yaml:"allow_registration"`
	DefaultAdmin      AdminConfig  `yaml:"default_admin"`
}

type AdminConfig struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
}

type ProvidersConfig struct {
	Default        string                    `yaml:"default"`
	Anthropic      ProviderConfig            `yaml:"anthropic"`
	OpenAI         ProviderConfig            `yaml:"openai"`
	Ollama         ProviderConfig            `yaml:"ollama"`
	Groq           ProviderConfig            `yaml:"groq"`
	Azure          ProviderConfig            `yaml:"azure"`
	FallbackChain  []string                  `yaml:"fallback_chain"`
	Embedding      EmbeddingConfig           `yaml:"embedding"`
	AgentOverrides map[string]string         `yaml:"agent_overrides"`
}

type ProviderConfig struct {
	APIKey    string `yaml:"api_key"`
	BaseURL   string `yaml:"base_url"`
	Model     string `yaml:"model"`
	MaxTokens int    `yaml:"max_tokens"`
}

type EmbeddingConfig struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
}

type MCPConfig struct {
	Server MCPServerConfig `yaml:"server"`
	Stdio  struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"stdio"`
	Federation struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"federation"`
}

type MCPServerConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	AuthToken string `yaml:"auth_token"`
}

type AgentConfig struct {
	MaxIterations    int `yaml:"max_iterations"`
	MaxParallelTools int `yaml:"max_parallel_tools"`
	ThinkingBudget   int `yaml:"thinking_budget"`
	AutoReview       bool `yaml:"auto_review"`
}

type ToolsConfig struct {
	Dir     string        `yaml:"dir"`
	Docker  DockerConfig  `yaml:"docker"`
	Process ProcessConfig `yaml:"process"`
}

type DockerConfig struct {
	Enabled        bool          `yaml:"enabled"`
	DefaultTimeout time.Duration `yaml:"default_timeout"`
	DefaultMemory  string        `yaml:"default_memory"`
	DefaultCPU     string        `yaml:"default_cpu"`
	Network        string        `yaml:"network"`
	CleanupAfter   bool          `yaml:"cleanup_after"`
}

type ProcessConfig struct {
	Enabled bool          `yaml:"enabled"`
	Timeout time.Duration `yaml:"timeout"`
}

type DirConfig struct {
	Dir string `yaml:"dir"`
}

type KnowledgeConfig struct {
	Enabled   bool              `yaml:"enabled"`
	Dir       string            `yaml:"dir"`
	Retrieval RetrievalConfig   `yaml:"retrieval"`
}

type RetrievalConfig struct {
	TopK                int     `yaml:"top_k"`
	SimilarityThreshold float64 `yaml:"similarity_threshold"`
	HybridWeight        float64 `yaml:"hybrid_weight"`
}

type SchedulerConfig struct {
	Enabled bool `yaml:"enabled"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// Load reads configuration from file and environment variables.
func Load() (*Config, error) {
	cfg := defaults()

	// Try config file paths in order
	paths := []string{
		os.Getenv("CONFIG_PATH"),
		"config.yaml",
		"/app/config.yaml",
		"/etc/phantomstrike/config.yaml",
	}

	for _, p := range paths {
		if p == "" {
			continue
		}
		if data, err := os.ReadFile(p); err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parsing config %s: %w", p, err)
			}
			break
		}
	}

	// Override with environment variables
	applyEnvOverrides(cfg)

	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8080,
			CORSOrigins:    []string{"http://localhost:5173"},
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   120 * time.Second,
			MaxRequestBody: "50mb",
		},
		Database: DatabaseConfig{
			MaxConnections: 25,
			MigrationAuto:  true,
		},
		Auth: AuthConfig{
			TokenExpiry:       24 * time.Hour,
			RefreshExpiry:     7 * 24 * time.Hour,
			AllowRegistration: true,
			DefaultAdmin: AdminConfig{
				Email: "admin@phantomstrike.local",
			},
		},
		Providers: ProvidersConfig{
			Default:       "anthropic",
			FallbackChain: []string{"anthropic", "openai", "ollama"},
			Anthropic:     ProviderConfig{Model: "claude-sonnet-4-20250514", MaxTokens: 8192},
			OpenAI:        ProviderConfig{Model: "gpt-4o"},
			Embedding:     EmbeddingConfig{Provider: "openai", Model: "text-embedding-3-large"},
		},
		MCP: MCPConfig{
			Server: MCPServerConfig{
				Enabled: true,
				Host:    "0.0.0.0",
				Port:    8081,
			},
		},
		Agent: AgentConfig{
			MaxIterations:    30,
			MaxParallelTools: 3,
			ThinkingBudget:   8192,
			AutoReview:       true,
		},
		Tools: ToolsConfig{
			Dir: "tools",
			Docker: DockerConfig{
				Enabled:        true,
				DefaultTimeout: 5 * time.Minute,
				DefaultMemory:  "512m",
				DefaultCPU:     "1.0",
				Network:        "phantomstrike-tools",
				CleanupAfter:   true,
			},
			Process: ProcessConfig{
				Enabled: true,
				Timeout: 5 * time.Minute,
			},
		},
		Roles:  DirConfig{Dir: "roles"},
		Skills: DirConfig{Dir: "skills"},
		Knowledge: KnowledgeConfig{
			Enabled: true,
			Dir:     "knowledge",
			Retrieval: RetrievalConfig{
				TopK:                5,
				SimilarityThreshold: 0.7,
				HybridWeight:        0.7,
			},
		},
		Scheduler: SchedulerConfig{Enabled: true},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9090,
		},
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.Database.URL = v
	}
	if v := os.Getenv("REDIS_URL"); v != "" {
		cfg.Redis.URL = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("ADMIN_PASSWORD"); v != "" {
		cfg.Auth.DefaultAdmin.Password = v
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		cfg.Providers.Anthropic.APIKey = v
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		cfg.Providers.OpenAI.APIKey = v
	}
	if v := os.Getenv("GROQ_API_KEY"); v != "" {
		cfg.Providers.Groq.APIKey = v
	}
	if v := os.Getenv("MCP_AUTH_TOKEN"); v != "" {
		cfg.MCP.Server.AuthToken = v
	}
	if v := os.Getenv("STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}

	// Expand ${VAR} references in string fields already loaded from YAML
	cfg.Database.URL = expandEnv(cfg.Database.URL)
	cfg.Redis.URL = expandEnv(cfg.Redis.URL)
	cfg.Auth.JWTSecret = expandEnv(cfg.Auth.JWTSecret)
	cfg.Auth.DefaultAdmin.Password = expandEnv(cfg.Auth.DefaultAdmin.Password)
	cfg.Providers.Anthropic.APIKey = expandEnv(cfg.Providers.Anthropic.APIKey)
	cfg.Providers.OpenAI.APIKey = expandEnv(cfg.Providers.OpenAI.APIKey)
	cfg.Providers.Groq.APIKey = expandEnv(cfg.Providers.Groq.APIKey)
	cfg.MCP.Server.AuthToken = expandEnv(cfg.MCP.Server.AuthToken)
}

// expandEnv replaces ${VAR} patterns with environment variable values.
func expandEnv(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return os.ExpandEnv(s)
}
