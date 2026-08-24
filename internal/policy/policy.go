package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name      string    `json:"name" yaml:"name"`
	RateLimit RateLimit `json:"rate_limit" yaml:"rate_limit"`
	Backoff   Backoff   `json:"backoff" yaml:"backoff"`
	Pause     Pause     `json:"pause" yaml:"pause"`
	Scope     Scope     `json:"scope" yaml:"scope"`
}

type RateLimit struct {
	RequestsPerSecond int `json:"requests_per_second" yaml:"requests_per_second"`
	RequestsPerMinute int `json:"requests_per_minute" yaml:"requests_per_minute"`
	MaxConcurrency    int `json:"max_concurrency" yaml:"max_concurrency"`
	JitterMs          int `json:"jitter_ms" yaml:"jitter_ms"`
}

type Backoff struct {
	OnStatus       []int `json:"on_status" yaml:"on_status"`
	InitialSeconds int   `json:"initial_seconds" yaml:"initial_seconds"`
	Multiplier     int   `json:"multiplier" yaml:"multiplier"`
	MaxSeconds     int   `json:"max_seconds" yaml:"max_seconds"`
}

type Pause struct {
	OnCaptcha bool `json:"on_captcha" yaml:"on_captcha"`
	OnIPBlock bool `json:"on_ip_block" yaml:"on_ip_block"`
}

type Scope struct {
	AllowedMethods []string `json:"allowed_methods" yaml:"allowed_methods"`
	DeniedMethods  []string `json:"denied_methods" yaml:"denied_methods"`
	MaxRequests    int      `json:"max_requests" yaml:"max_requests"`
}

type Store struct {
	db        *core.DB
	projectID string
}

func NewStore(db *core.DB, projectID string) *Store {
	return &Store{db: db, projectID: projectID}
}

func (s *Store) Create(name, yamlContent string) (*Config, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("policy name is required")
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return nil, "", fmt.Errorf("invalid policy yaml: %w", err)
	}
	if cfg.Name == "" {
		cfg.Name = name
	}
	if err := Validate(&cfg); err != nil {
		return nil, "", err
	}
	id := core.NewID("pol")
	now := core.TimestampNow()
	_, err := s.db.Conn().Exec(
		`INSERT INTO policies (id, project_id, name, config_yaml, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, s.projectID, name, yamlContent, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, "", fmt.Errorf("policy %q already exists", name)
		}
		return nil, "", err
	}
	return &cfg, id, nil
}

func (s *Store) Get(identifier string) (*Config, string, error) {
	var id, name, yamlContent, createdAt string
	err := s.db.Conn().QueryRow(
		`SELECT id, name, config_yaml, created_at FROM policies WHERE (id = ? OR name = ?) AND project_id = ?`,
		identifier, identifier, s.projectID,
	).Scan(&id, &name, &yamlContent, &createdAt)
	if err != nil {
		return nil, "", fmt.Errorf("policy %q not found", identifier)
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return nil, "", err
	}
	return &cfg, id, nil
}

func (s *Store) List() ([]map[string]string, error) {
	rows, err := s.db.Conn().Query(`SELECT id, name, created_at FROM policies WHERE project_id = ? ORDER BY created_at`, s.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, name, createdAt string
		rows.Scan(&id, &name, &createdAt)
		out = append(out, map[string]string{"id": id, "name": name, "created_at": createdAt})
	}
	return out, rows.Err()
}

func (s *Store) Delete(identifier string) error {
	res, err := s.db.Conn().Exec(`DELETE FROM policies WHERE (id = ? OR name = ?) AND project_id = ?`, identifier, identifier, s.projectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy %q not found", identifier)
	}
	return nil
}

func Validate(cfg *Config) error {
	if cfg.RateLimit.RequestsPerSecond < 0 || cfg.RateLimit.RequestsPerMinute < 0 {
		return fmt.Errorf("rate limit must be >= 0")
	}
	if cfg.RateLimit.MaxConcurrency < 0 {
		return fmt.Errorf("max_concurrency must be >= 0")
	}
	if cfg.Backoff.Multiplier < 0 {
		return fmt.Errorf("backoff multiplier must be >= 0")
	}
	return nil
}

func ParseYAML(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func ToJSON(yamlContent string) (json.RawMessage, error) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return nil, err
	}
	b, err := json.Marshal(cfg)
	return json.RawMessage(b), err
}

func BackoffDelay(cfg *Config, attempt int) time.Duration {
	if cfg.Backoff.InitialSeconds <= 0 {
		return 0
	}
	delay := time.Duration(cfg.Backoff.InitialSeconds) * time.Second
	mult := cfg.Backoff.Multiplier
	if mult <= 0 {
		mult = 2
	}
	for i := 1; i < attempt; i++ {
		delay *= time.Duration(mult)
		if cfg.Backoff.MaxSeconds > 0 && delay > time.Duration(cfg.Backoff.MaxSeconds)*time.Second {
			delay = time.Duration(cfg.Backoff.MaxSeconds) * time.Second
			break
		}
	}
	if cfg.RateLimit.JitterMs > 0 {
		delay += time.Duration(cfg.RateLimit.JitterMs) * time.Millisecond
	}
	return delay
}

func ShouldBackoff(cfg *Config, status int) bool {
	for _, s := range cfg.Backoff.OnStatus {
		if s == status {
			return true
		}
	}
	if status == 429 {
		return true
	}
	return false
}
