package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name  string            `yaml:"name" json:"name"`
	Steps []Step            `yaml:"steps" json:"steps"`
	Vars  map[string]string `yaml:"vars,omitempty" json:"vars,omitempty"`
}

type Step struct {
	Name    string            `yaml:"name" json:"name"`
	Request *RequestDef       `yaml:"request,omitempty" json:"request,omitempty"`
	Extract map[string]string `yaml:"extract,omitempty" json:"extract,omitempty"`
}

type RequestDef struct {
	Method  string            `yaml:"method" json:"method"`
	URL     string            `yaml:"url" json:"url"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	JSON    interface{}       `yaml:"json,omitempty" json:"json,omitempty"`
	Body    string            `yaml:"body,omitempty" json:"body,omitempty"`
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
		return "", fmt.Errorf("invalid workflow yaml: %w", err)
	}
	if name != "" && cfg.Name == "" {
		cfg.Name = name
	}
	if cfg.Name == "" {
		return "", fmt.Errorf("workflow name is required (set name: in yaml or pass --name)")
	}
	if name == "" {
		name = cfg.Name
	}
	if len(cfg.Steps) == 0 {
		return "", fmt.Errorf("workflow must have at least one step")
	}
	id := core.NewID("wf")
	now := core.TimestampNow()
	_, err := s.db.Conn().Exec(
		`INSERT INTO workflows (id, project_id, name, config_yaml, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, s.projectID, name, yamlContent, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("workflow %q already exists", name)
		}
		return "", err
	}
	return id, nil
}

func (s *Store) Get(identifier string) (string, string, *Config, error) {
	var id, name, yamlContent, createdAt string
	err := s.db.Conn().QueryRow(
		`SELECT id, name, config_yaml, created_at FROM workflows WHERE (id = ? OR name = ?) AND project_id = ?`,
		identifier, identifier, s.projectID,
	).Scan(&id, &name, &yamlContent, &createdAt)
	if err != nil {
		return "", "", nil, fmt.Errorf("workflow %q not found", identifier)
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlContent), &cfg); err != nil {
		return "", "", nil, err
	}
	return id, yamlContent, &cfg, nil
}

func (s *Store) List() ([]map[string]string, error) {
	rows, err := s.db.Conn().Query(`SELECT id, name, created_at FROM workflows WHERE project_id = ? ORDER BY created_at`, s.projectID)
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
	res, err := s.db.Conn().Exec(`DELETE FROM workflows WHERE (id = ? OR name = ?) AND project_id = ?`, identifier, identifier, s.projectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("workflow %q not found", identifier)
	}
	return nil
}

func ParseYAML(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("workflow name is required")
	}
	if len(cfg.Steps) == 0 {
		return nil, fmt.Errorf("workflow must have at least one step")
	}
	return &cfg, nil
}

type Runner struct {
	db         *core.DB
	projectID  string
	workflowID string
	config     *Config
	client     *http.Client
	state      map[string]string
}

func NewRunner(db *core.DB, projectID, workflowID string, cfg *Config) *Runner {
	return &Runner{
		db: db, projectID: projectID, workflowID: workflowID, config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		state:  map[string]string{},
	}
}

func (r *Runner) Run(ctx context.Context, dryRun bool) (map[string]string, error) {
	runID := core.NewID("wfrun")
	now := core.TimestampNow()
	stateJSON, _ := json.Marshal(r.state)

	if !dryRun {
		r.db.Conn().Exec(
			`INSERT INTO workflow_runs (id, workflow_id, project_id, status, state_json, started_at) VALUES (?, ?, ?, ?, ?, ?)`,
			runID, r.workflowID, r.projectID, "running", string(stateJSON), now,
		)
	}

	for _, step := range r.config.Steps {
		if dryRun {
			continue
		}
		if step.Request == nil {
			continue
		}

		urlStr := interpolate(step.Request.URL, r.state)
		method := step.Request.Method
		if method == "" {
			method = "GET"
		}
		var body []byte
		var contentType string
		if step.Request.JSON != nil {

			jsonStr, _ := json.Marshal(step.Request.JSON)
			interpolated := interpolate(string(jsonStr), r.state)
			body = []byte(interpolated)
			contentType = "application/json"
		} else if step.Request.Body != "" {
			body = []byte(interpolate(step.Request.Body, r.state))
		}

		req, err := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewReader(body))
		if err != nil {
			r.failRun(runID, err.Error())
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range step.Request.Headers {
			req.Header.Set(k, interpolate(v, r.state))
		}

		resp, err := r.client.Do(req)
		if err != nil {
			r.failRun(runID, err.Error())
			return nil, fmt.Errorf("step %q: %w", step.Name, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		for varName, expr := range step.Extract {
			val := extractValue(respBody, resp.Header, expr)
			if val != "" {
				r.state[varName] = val
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	finalState, _ := json.Marshal(r.state)
	if !dryRun {
		r.db.Conn().Exec(
			`UPDATE workflow_runs SET status = ?, state_json = ?, finished_at = ? WHERE id = ?`,
			"done", string(finalState), core.TimestampNow(), runID,
		)
	}
	return r.state, nil
}

func (r *Runner) failRun(runID, errMsg string) {
	r.db.Conn().Exec(`UPDATE workflow_runs SET status = ?, error = ?, finished_at = ? WHERE id = ?`, "failed", errMsg, core.TimestampNow(), runID)
}

func interpolate(s string, state map[string]string) string {
	re := regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		key := re.FindStringSubmatch(m)[1]
		if v, ok := state[key]; ok {
			return v
		}
		return m
	})
}

func extractValue(body []byte, headers http.Header, expr string) string {
	if strings.HasPrefix(expr, "header:") {
		h := strings.TrimPrefix(expr, "header:")
		return headers.Get(h)
	}
	if strings.HasPrefix(expr, "$.") {
		path := strings.TrimPrefix(expr, "$.")
		var obj interface{}
		if err := json.Unmarshal(body, &obj); err != nil {
			return ""
		}
		parts := strings.Split(path, ".")
		cur := obj
		for _, p := range parts {
			if m, ok := cur.(map[string]interface{}); ok {
				cur = m[p]
			} else {
				return ""
			}
		}
		if s, ok := cur.(string); ok {
			return s
		}
		if cur != nil {
			b, _ := json.Marshal(cur)
			return string(b)
		}
	}

	re, err := regexp.Compile(expr)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(string(body))
	if len(m) > 1 {
		return m[1]
	}
	if len(m) == 1 {
		return m[0]
	}
	return ""
}
