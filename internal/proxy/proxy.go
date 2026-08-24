package proxy

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	px "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/scope"
)

type Config struct {
	ListenAddr    string
	ProjectDir    string
	ProjectID     string
	UpstreamProxy string
	SilentMode    bool
}

type Server struct {
	proxy   *px.Proxy
	capture *CaptureAddon
	cfg     Config
}

func New(db *core.DB, scopeEngine *scope.Engine, auditLog *scope.AuditLogger, cfg Config) (*Server, error) {
	caDir := filepath.Join(cfg.ProjectDir, "ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}

	opts := &px.Options{
		Addr:              cfg.ListenAddr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       false,
		CaRootPath:        caDir,
	}

	if cfg.UpstreamProxy != "" {
		opts.Upstream = cfg.UpstreamProxy
	}

	p, err := px.NewProxy(opts)
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}

	if cfg.SilentMode {
		log.SetOutput(os.Stderr)
	}

	capture := newCaptureAddon(db, scopeEngine, auditLog, cfg)
	p.AddAddon(capture)

	return &Server{proxy: p, capture: capture, cfg: cfg}, nil
}

func (s *Server) Start() error {
	fmt.Printf("AgentBurp proxy listening on %s\n", s.cfg.ListenAddr)
	fmt.Printf("CA certificate: %s\n", filepath.Join(s.cfg.ProjectDir, "ca", "mitmproxy-ca-cert.pem"))
	return s.proxy.Start()
}

type CaptureAddon struct {
	px.BaseAddon
	db    *core.DB
	scope *scope.Engine
	audit *scope.AuditLogger
	cfg   Config
	rules []InterceptRule
}

type InterceptRule struct {
	Match  RuleMatch `json:"match"`
	Action string    `json:"action"`
}
type RuleMatch struct {
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Method string `json:"method,omitempty"`
}

func newCaptureAddon(db *core.DB, s *scope.Engine, a *scope.AuditLogger, cfg Config) *CaptureAddon {
	return &CaptureAddon{db: db, scope: s, audit: a, cfg: cfg}
}

func (c *CaptureAddon) Request(f *px.Flow) {
	req := f.Request
	rawURL := req.URL.String()
	if !c.scope.IsInScope(rawURL) {
		result := c.scope.Check(rawURL)
		c.audit.LogScopeViolation(rawURL, result.Reason)
		f.Response = &px.Response{
			StatusCode: 421,
			Header: http.Header{
				"Content-Type":        []string{"application/json"},
				"X-AgentBurp-Blocked": []string{"scope-violation"},
			},
			Body: []byte(`{"error":"scope_violation","message":"request blocked by AgentBurp scope engine"}`),
		}
		return
	}

	for _, rule := range c.rules {
		if matchesRule(rule.Match, req) {
			if rule.Action == "drop" {
				f.Response = &px.Response{
					StatusCode: 421,
					Body:       []byte(`{"error":"dropped","message":"request dropped by intercept rule"}`),
				}
				return
			}
			break
		}
	}
}

func (c *CaptureAddon) Response(f *px.Flow) {
	if f.Request == nil || f.Response == nil {
		return
	}
	if err := c.saveExchange(f); err != nil {
		if !c.cfg.SilentMode {
			fmt.Fprintf(os.Stderr, "capture error: %v\n", err)
		}
	}
}
