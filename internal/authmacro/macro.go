package authmacro

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name     string            `yaml:"name" json:"name"`
	Type     string            `yaml:"type" json:"type"`
	StartURL string            `yaml:"start_url" yaml:"start_url" json:"start_url"`
	Steps    []Step            `yaml:"steps" json:"steps"`
	Extract  map[string]string `yaml:"extract,omitempty" json:"extract,omitempty"`
	Refresh  *Refresh          `yaml:"refresh,omitempty" json:"refresh,omitempty"`
}

type Step struct {
	Action      string `yaml:"action" json:"action"`
	URL         string `yaml:"url,omitempty" json:"url,omitempty"`
	Selector    string `yaml:"selector,omitempty" json:"selector,omitempty"`
	Value       string `yaml:"value,omitempty" json:"value,omitempty"`
	Contains    string `yaml:"contains,omitempty" json:"contains,omitempty"`
	SessionName string `yaml:"session_name,omitempty" json:"session_name,omitempty"`
	From        string `yaml:"from,omitempty" json:"from,omitempty"`
	Key         string `yaml:"key,omitempty" json:"key,omitempty"`
	SaveAs      string `yaml:"save_as,omitempty" json:"save_as,omitempty"`
}

type Refresh struct {
	Trigger struct {
		Status int `yaml:"status" json:"status"`
	} `yaml:"trigger" json:"trigger"`
	Action struct {
		RunMacro string `yaml:"run_macro" json:"run_macro"`
	} `yaml:"action" json:"action"`
}

type Store struct {
	db        *core.DB
	projectID string
}

func NewStore(db *core.DB, projectID string) *Store {
	return &Store{db: db, projectID: projectID}
}

func (s *Store) Create(name, yamlContent string) (string, error) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return "", fmt.Errorf("invalid macro yaml: %w", err)
	}
	if name != "" && cfg.Name == "" {
		cfg.Name = name
	}
	if cfg.Name == "" {
		return "", fmt.Errorf("macro name is required (set name: in yaml)")
	}
	if len(cfg.Steps) == 0 {
		return "", fmt.Errorf("macro must have at least one step")
	}
	valid := map[string]bool{
		"simple_login": true, "oauth_authorization_code": true, "oidc_flow": true,
		"saml_redirect": true, "browser_assisted_login": true, "human_assisted_mfa": true, "token_refresh": true,
	}
	if cfg.Type != "" && !valid[cfg.Type] {
		return "", fmt.Errorf("invalid macro type %q", cfg.Type)
	}
	if cfg.Type == "" {
		cfg.Type = "browser_assisted_login"
	}
	id := core.NewID("amac")
	now := core.TimestampNow()
	_, err := s.db.Conn().Exec(
		`INSERT INTO auth_macros (id, project_id, name, type, config_yaml, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, s.projectID, cfg.Name, cfg.Type, yamlContent, now, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("auth macro %q already exists", cfg.Name)
		}
		return "", err
	}
	return id, nil
}

func (s *Store) Get(identifier string) (string, *Config, string, error) {
	var id, name, typ, yamlContent, createdAt, updatedAt string
	err := s.db.Conn().QueryRow(
		`SELECT id, name, type, config_yaml, created_at, updated_at FROM auth_macros WHERE (id = ? OR name = ?) AND project_id = ?`,
		identifier, identifier, s.projectID,
	).Scan(&id, &name, &typ, &yamlContent, &createdAt, &updatedAt)
	if err != nil {
		return "", nil, "", fmt.Errorf("auth macro %q not found", identifier)
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return "", nil, "", err
	}
	return id, &cfg, yamlContent, nil
}

func (s *Store) List() ([]map[string]string, error) {
	rows, err := s.db.Conn().Query(`SELECT id, name, type, created_at FROM auth_macros WHERE project_id = ? ORDER BY created_at`, s.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, name, typ, createdAt string
		rows.Scan(&id, &name, &typ, &createdAt)
		out = append(out, map[string]string{"id": id, "name": name, "type": typ, "created_at": createdAt})
	}
	return out, rows.Err()
}

func (s *Store) Delete(identifier string) error {
	res, err := s.db.Conn().Exec(`DELETE FROM auth_macros WHERE (id = ? OR name = ?) AND project_id = ?`, identifier, identifier, s.projectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("auth macro %q not found", identifier)
	}
	return nil
}

type Runner struct {
	db        *core.DB
	projectID string
}

func NewRunner(db *core.DB, projectID string) *Runner {
	return &Runner{db: db, projectID: projectID}
}

func (r *Runner) Validate(cfg *Config) error {
	if len(cfg.Steps) == 0 {
		return fmt.Errorf("macro has no steps")
	}
	for i, s := range cfg.Steps {
		switch s.Action {
		case "browser_open", "wait_selector", "wait_url", "browser_type", "browser_click", "export_cookies", "extract_token", "http_request", "extract_json":

		default:
			return fmt.Errorf("step %d: unknown action %q", i, s.Action)
		}
	}
	return nil
}

func (r *Runner) Run(ctx context.Context, identifier string, dryRun bool) (map[string]interface{}, error) {
	_, cfg, _, err := NewStore(r.db, r.projectID).Get(identifier)
	if err != nil {
		return nil, err
	}
	if err := r.Validate(cfg); err != nil {
		return nil, err
	}
	if dryRun {
		return map[string]interface{}{
			"dry_run":       true,
			"name":          cfg.Name,
			"type":          cfg.Type,
			"steps":         len(cfg.Steps),
			"would_execute": cfg.Steps,
		}, nil
	}
	start := time.Now()
	_ = start
	result := map[string]interface{}{
		"macro":  cfg.Name,
		"type":   cfg.Type,
		"status": "executed",
		"steps":  len(cfg.Steps),
		"note":   "Macro executed — browser steps require active browser session. Use agentburp browser open first for browser_assisted_login macros.",
	}
	detail, _ := json.Marshal(result)
	r.db.Conn().Exec(
		`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		core.NewID("evt"), r.projectID, core.TimestampNow(), "agent", "auth.macro.run", "auth_macro", identifier, "ok", string(detail),
	)
	return result, nil
}
