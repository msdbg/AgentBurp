package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

type Type string

const (
	TypeRawHTTP           Type = "raw-http"
	TypeFastHTTP          Type = "fast-http"
	TypeBrowserSession    Type = "browser-session"
	TypeBrowserFetch      Type = "browser-fetch"
	TypeExternalTransport Type = "external-transport"
)

var ValidTypes = map[Type]bool{
	TypeRawHTTP:           true,
	TypeFastHTTP:          true,
	TypeBrowserSession:    true,
	TypeBrowserFetch:      true,
	TypeExternalTransport: true,
}

type Profile struct {
	ID        string          `json:"id"`
	ProjectID string          `json:"project_id"`
	Name      string          `json:"name"`
	Type      Type            `json:"type"`
	Config    json.RawMessage `json:"config"`
	CreatedAt string          `json:"created_at"`
}

type OutboundRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	TimeMs     int64
}

type Transport interface {
	Send(ctx context.Context, req *OutboundRequest) (*Response, error)
	Name() string
	SupportsCookies() bool
	SupportsJS() bool
	Type() Type
}

type Registry struct {
	factories map[Type]func(profile *Profile) Transport
}

func NewRegistry() *Registry {
	r := &Registry{factories: map[Type]func(profile *Profile) Transport{}}
	r.factories[TypeRawHTTP] = func(p *Profile) Transport { return NewRawHTTP(p) }
	r.factories[TypeFastHTTP] = func(p *Profile) Transport { return NewFastHTTP(p) }
	r.factories[TypeBrowserSession] = func(p *Profile) Transport { return NewBrowserSessionTransport(p) }
	r.factories[TypeBrowserFetch] = func(p *Profile) Transport { return NewBrowserFetchTransport(p) }
	r.factories[TypeExternalTransport] = func(p *Profile) Transport { return NewExternalTransport(p) }
	return r
}

func (r *Registry) Create(profile *Profile) (Transport, error) {
	f, ok := r.factories[profile.Type]
	if !ok {
		return nil, fmt.Errorf("unknown transport type %q — valid: raw-http, fast-http, browser-session, browser-fetch, external-transport", profile.Type)
	}
	return f(profile), nil
}

type Store struct {
	db        *core.DB
	projectID string
}

func NewStore(db *core.DB, projectID string) *Store {
	return &Store{db: db, projectID: projectID}
}

func (s *Store) Create(name string, t Type, configJSON string) (*Profile, error) {
	if name == "" {
		return nil, fmt.Errorf("transport name is required")
	}
	if !ValidTypes[t] {
		return nil, fmt.Errorf("invalid transport type %q — valid: raw-http, fast-http, browser-session, browser-fetch, external-transport", t)
	}
	if configJSON == "" {
		configJSON = "{}"
	}
	var js json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &js); err != nil {
		return nil, fmt.Errorf("invalid config_json: %w", err)
	}
	id := core.NewID("trans")
	now := core.TimestampNow()
	_, err := s.db.Conn().Exec(
		`INSERT INTO transport_profiles (id, project_id, name, type, config_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, s.projectID, name, string(t), configJSON, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("transport profile %q already exists in this project", name)
		}
		return nil, err
	}
	return &Profile{ID: id, ProjectID: s.projectID, Name: name, Type: t, Config: json.RawMessage(configJSON), CreatedAt: now}, nil
}

func (s *Store) GetByName(name string) (*Profile, error) {
	return s.get(`SELECT id, project_id, name, type, config_json, created_at FROM transport_profiles WHERE project_id = ? AND name = ?`, s.projectID, name)
}
func (s *Store) GetByID(id string) (*Profile, error) {
	return s.get(`SELECT id, project_id, name, type, config_json, created_at FROM transport_profiles WHERE id = ? AND project_id = ?`, id, s.projectID)
}

func (s *Store) Resolve(identifier string) (*Profile, error) {
	if identifier == "" {
		return nil, fmt.Errorf("transport identifier is required")
	}
	if p, err := s.GetByID(identifier); err == nil {
		return p, nil
	}
	if p, err := s.GetByName(identifier); err == nil {
		return p, nil
	}
	if ValidTypes[Type(identifier)] {
		return &Profile{
			ID:        "ephemeral_" + identifier,
			ProjectID: s.projectID,
			Name:      identifier,
			Type:      Type(identifier),
			Config:    json.RawMessage(`{}`),
			CreatedAt: core.TimestampNow(),
		}, nil
	}
	return nil, fmt.Errorf("transport %q not found — use: agentburp transport list", identifier)
}

func (s *Store) List() ([]*Profile, error) {
	rows, err := s.db.Conn().Query(
		`SELECT id, project_id, name, type, config_json, created_at FROM transport_profiles WHERE project_id = ? ORDER BY created_at`, s.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Profile
	for rows.Next() {
		var p Profile
		var typ, cfg string
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.Name, &typ, &cfg, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Type = Type(typ)
		p.Config = json.RawMessage(cfg)
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *Store) Delete(identifier string) error {
	res, err := s.db.Conn().Exec(`DELETE FROM transport_profiles WHERE (id = ? OR name = ?) AND project_id = ?`, identifier, identifier, s.projectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("transport profile %q not found", identifier)
	}
	return nil
}

func (s *Store) get(query string, args ...interface{}) (*Profile, error) {
	var p Profile
	var typ, cfg string
	err := s.db.Conn().QueryRow(query, args...).Scan(&p.ID, &p.ProjectID, &p.Name, &typ, &cfg, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("transport profile not found: %w", err)
	}
	p.Type = Type(typ)
	p.Config = json.RawMessage(cfg)
	return &p, nil
}

type rawHTTP struct {
	profile *Profile
	client  *http.Client
}

func NewRawHTTP(p *Profile) Transport {
	return &rawHTTP{
		profile: p,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (t *rawHTTP) Name() string          { return "raw-http" }
func (t *rawHTTP) Type() Type            { return TypeRawHTTP }
func (t *rawHTTP) SupportsCookies() bool { return true }
func (t *rawHTTP) SupportsJS() bool      { return false }

func (t *rawHTTP) Send(ctx context.Context, req *OutboundRequest) (*Response, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("transport %q: %w", t.Name(), err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       b,
		TimeMs:     time.Since(start).Milliseconds(),
	}, nil
}

type fastHTTP struct {
	profile *Profile
	client  *http.Client
}

func NewFastHTTP(p *Profile) Transport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	return &fastHTTP{
		profile: p,
		client:  &http.Client{Transport: transport, Timeout: 15 * time.Second},
	}
}

func (t *fastHTTP) Name() string          { return "fast-http" }
func (t *fastHTTP) Type() Type            { return TypeFastHTTP }
func (t *fastHTTP) SupportsCookies() bool { return true }
func (t *fastHTTP) SupportsJS() bool      { return false }

func (t *fastHTTP) Send(ctx context.Context, req *OutboundRequest) (*Response, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fast-http transport: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &Response{StatusCode: resp.StatusCode, Headers: resp.Header, Body: b, TimeMs: time.Since(start).Milliseconds()}, nil
}

type browserSession struct {
	profile *Profile
}

func NewBrowserSessionTransport(p *Profile) Transport {
	return &browserSession{profile: p}
}

func (t *browserSession) Name() string          { return "browser-session" }
func (t *browserSession) Type() Type            { return TypeBrowserSession }
func (t *browserSession) SupportsCookies() bool { return true }
func (t *browserSession) SupportsJS() bool      { return false }

func (t *browserSession) Send(ctx context.Context, req *OutboundRequest) (*Response, error) {
	r := NewRawHTTP(t.profile)
	return r.Send(ctx, req)
}

type browserFetch struct {
	profile *Profile
}

func NewBrowserFetchTransport(p *Profile) Transport {
	return &browserFetch{profile: p}
}

func (t *browserFetch) Name() string          { return "browser-fetch" }
func (t *browserFetch) Type() Type            { return TypeBrowserFetch }
func (t *browserFetch) SupportsCookies() bool { return true }
func (t *browserFetch) SupportsJS() bool      { return true }

func (t *browserFetch) Send(ctx context.Context, req *OutboundRequest) (*Response, error) {
	return nil, fmt.Errorf("browser-fetch transport requires an active browser session — use: agentburp browser open <url> then agentburp browser fetch --method %s --url %s", req.Method, req.URL)
}

type externalTransport struct {
	profile *Profile
}

func NewExternalTransport(p *Profile) Transport {
	return &externalTransport{profile: p}
}

func (t *externalTransport) Name() string          { return "external-transport" }
func (t *externalTransport) Type() Type            { return TypeExternalTransport }
func (t *externalTransport) SupportsCookies() bool { return false }
func (t *externalTransport) SupportsJS() bool      { return false }

func (t *externalTransport) Send(ctx context.Context, req *OutboundRequest) (*Response, error) {
	if t.profile == nil || len(t.profile.Config) == 0 || string(t.profile.Config) == "{}" {
		return nil, fmt.Errorf("external-transport requires config_json with adapter command — create with --config '{\"command\":\"./my_adapter\"}'")
	}
	return nil, fmt.Errorf("external-transport adapter not configured for this profile")
}

func ApplySession(headers map[string]string, sess *models.Session, store *auth.SessionStore) map[string]string {
	if sess == nil {
		return headers
	}
	if headers == nil {
		headers = map[string]string{}
	}
	h := make([]models.Header, 0, len(headers))
	for k, v := range headers {
		h = append(h, models.Header{Name: k, Value: v})
	}
	h = store.ApplyToRequest(sess, h)
	out := map[string]string{}
	for _, hdr := range h {
		out[hdr.Name] = hdr.Value
	}
	return out
}

func EnrichURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", rawURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid url %q: missing scheme or host", rawURL)
	}
	return nil
}
