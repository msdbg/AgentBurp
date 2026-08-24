package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentctx "github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/httpclient"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/scope"
)

type Options struct {
	Target      string
	MaxDepth    int
	Headless    bool
	SessionID   string
	Rate        int
	Concurrency int
	MaxPages    int
	ProxyURL    string
}

type Runner struct {
	db        *core.DB
	projectID string
	jobID     string
	store     *core.JobStore
	opts      Options
	client    *httpclient.Client
	audit     *scope.AuditLogger
	engine    *scope.Engine
	session   []models.Header

	mu         sync.Mutex
	visited    map[string]int
	discovered []string
	entries    []models.CrawlEntry
	formCount  int
	items      []crawlItem
	running    int
	sent       int64
	fetched    int64
}

type crawlItem struct {
	URL   string
	Depth int
	Via   string
}

func NewRunner(db *core.DB, proj *core.Project, jobID string, opts Options, session []models.Header) (*Runner, error) {
	engine, err := scope.NewEngine(db, proj.ID)
	if err != nil {
		return nil, err
	}
	if opts.Rate <= 0 {
		opts.Rate = 5
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 200
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 3
	}
	return &Runner{
		db:        db,
		projectID: proj.ID,
		jobID:     jobID,
		store:     core.NewJobStore(db),
		opts:      opts,
		client:    httpclient.New(httpclient.Options{Timeout: 30 * time.Second, FollowRedirects: true, RatePerSec: opts.Rate}),
		audit:     scope.NewAuditLogger(db, proj.ID),
		engine:    engine,
		session:   session,
		visited:   map[string]int{},
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.store.MarkRunning(r.jobID); err != nil {
		return err
	}
	r.mu.Lock()
	r.items = append(r.items, crawlItem{URL: NormalizeURL(r.opts.Target), Depth: 0, Via: "seed"})
	r.running++
	r.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < r.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if r.store.IsCancelled(r.jobID) {
					return
				}
				item, ok := r.pop()
				if !ok {
					return
				}
				r.fetch(ctx, item)
				r.markDone()
			}
		}()
	}
	wg.Wait()
	summary := r.buildSummary()
	if r.store.IsCancelled(r.jobID) {
		sJSON, _ := json.Marshal(summary)
		r.db.Conn().Exec(`UPDATE jobs SET result_summary_json = ? WHERE id = ?`, string(sJSON), r.jobID)
		return nil
	}
	return r.store.MarkDone(r.jobID, summary)
}

func (r *Runner) pop() (crawlItem, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if len(r.items) > 0 {
			it := r.items[0]
			r.items = r.items[1:]
			return it, true
		}
		if r.running == 0 {
			return crawlItem{}, false
		}
		r.mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		r.mu.Lock()
	}
}

func (r *Runner) markDone() {
	r.mu.Lock()
	r.running--
	r.mu.Unlock()
}

func (r *Runner) buildSummary() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	urls := make([]string, len(r.entries))
	for i, e := range r.entries {
		urls[i] = e.URL
	}
	if len(urls) > 500 {
		urls = urls[:500]
	}
	return map[string]interface{}{
		"target":          r.opts.Target,
		"headless":        r.opts.Headless,
		"pages_fetched":   atomic.LoadInt64(&r.fetched),
		"requests_sent":   atomic.LoadInt64(&r.sent),
		"forms_submitted": r.formCount,
		"urls_discovered": len(r.discovered),
		"max_depth":       r.opts.MaxDepth,
		"discovered_urls": urls,
		"endpoint_count":  r.endpointCount(),
	}
}

func (r *Runner) endpointCount() int {
	var n int
	r.db.Conn().QueryRow(`SELECT COUNT(*) FROM endpoints WHERE project_id = ?`, r.projectID).Scan(&n)
	return n
}

func (r *Runner) fetch(ctx context.Context, item crawlItem) error {
	if !r.engine.IsInScope(item.URL) {
		r.audit.LogScopeViolation(item.URL, "out of scope")
		return fmt.Errorf("out of scope: %s", item.URL)
	}
	r.mu.Lock()
	if d, ok := r.visited[item.URL]; ok && d <= item.Depth {
		r.mu.Unlock()
		return nil
	}
	if len(r.visited) >= r.opts.MaxPages {
		r.mu.Unlock()
		return nil
	}
	r.visited[item.URL] = item.Depth
	r.discovered = append(r.discovered, item.URL)
	r.mu.Unlock()

	headerMap := map[string]string{
		"User-Agent": "AgentBurp-Crawler/0.1",
		"Accept":     "text/html,application/xhtml+xml,application/json,application/javascript,*/*;q=0.8",
	}
	for _, s := range r.session {
		headerMap[s.Name] = s.Value
	}

	resp, body, err := r.client.Do(ctx, "GET", item.URL, headerMap, nil)
	if err != nil {
		return err
	}
	atomic.AddInt64(&r.sent, 1)

	var netURLs []string
	if r.opts.Headless {
		rendered, nets, err := r.render(ctx, item.URL)
		if err != nil {
			return err
		}
		if len(rendered) > 0 {
			body = rendered
		}
		netURLs = nets
	}
	r.recordEntries(ctx, item, resp, body, netURLs)
	return nil
}

func (r *Runner) recordEntries(ctx context.Context, item crawlItem, resp *http.Response, body []byte, netURLs []string) {
	reqID, respID := r.saveExchange(item.URL, resp, body)
	r.audit.LogRequestSent(reqID, "crawler")
	atomic.AddInt64(&r.fetched, 1)

	ct := resp.Header.Get("Content-Type")
	isJS := strings.Contains(ct, "javascript") || strings.HasSuffix(strings.ToLower(item.URL), ".js")

	var links []string
	var forms []Form
	if isJS {
		links = JSEndpointURLs(item.URL, string(body))
	} else if strings.Contains(ct, "html") || strings.Contains(ct, "text/plain") {
		links = ExtractLinks(item.URL, body)
		forms = ExtractForms(item.URL, body)
		for _, js := range ExtractInlineScripts(body) {
			links = append(links, JSEndpointURLs(item.URL, js)...)
		}
	}
	links = append(links, netURLs...)

	r.mu.Lock()
	r.entries = append(r.entries, models.CrawlEntry{
		URL: item.URL, Method: "GET", Status: resp.StatusCode, Depth: item.Depth,
		DiscoveredVia: item.Via, RequestID: reqID, ResponseID: respID,
	})
	nextDepth := item.Depth + 1
	var toQueue []crawlItem
	var toSubmit []formJob
	for _, u := range links {
		if len(toQueue) >= 50 {
			break
		}
		if !SameHost(u, item.URL) || IsStaticResource(u) {
			continue
		}
		if isDestructiveURL(u) {
			continue
		}
		if nextDepth > r.opts.MaxDepth {
			continue
		}
		nu := NormalizeURL(u)
		if nu == "" || nu == item.URL {
			continue
		}
		if _, seen := r.visited[nu]; seen {
			continue
		}
		if len(r.visited) >= r.opts.MaxPages {
			break
		}
		r.discovered = append(r.discovered, nu)
		r.running++
		toQueue = append(toQueue, crawlItem{URL: nu, Depth: nextDepth, Via: "link"})
	}
	for _, f := range forms {
		method, formURL, body := FormRequest(f)
		if !r.engine.IsInScope(formURL) {
			continue
		}
		r.formCount++
		toSubmit = append(toSubmit, formJob{Method: method, URL: formURL, Body: body})
	}
	r.items = append(r.items, toQueue...)
	r.mu.Unlock()

	for _, fj := range toSubmit {
		r.submitForm(ctx, fj)
	}
}

type formJob struct {
	Method string
	URL    string
	Body   []byte
}

func (r *Runner) submitForm(ctx context.Context, fj formJob) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	if !r.engine.IsInScope(fj.URL) {
		r.audit.LogScopeViolation(fj.URL, "out of scope")
		return
	}
	if isDestructiveURL(fj.URL) {
		return
	}
	headerMap := map[string]string{
		"User-Agent": "AgentBurp-Crawler/0.1",
	}
	for _, s := range r.session {
		headerMap[s.Name] = s.Value
	}
	if fj.Method == "POST" {
		headerMap["Content-Type"] = "application/x-www-form-urlencoded"
	}
	resp, body, err := r.client.Do(ctx, fj.Method, fj.URL, headerMap, fj.Body)
	if err != nil {
		return
	}
	atomic.AddInt64(&r.sent, 1)
	reqID, respID := r.saveExchangeWithBody(fj.URL, fj.Method, fj.Body, resp, body)
	r.audit.LogRequestSent(reqID, "crawler")
	_ = respID
	r.mu.Lock()
	r.entries = append(r.entries, models.CrawlEntry{
		URL: fj.URL, Method: fj.Method, Status: resp.StatusCode, Depth: r.opts.MaxDepth,
		DiscoveredVia: "form", RequestID: reqID, ResponseID: respID,
	})
	r.mu.Unlock()
}

func (r *Runner) saveExchange(rawURL string, resp *http.Response, body []byte) (string, string) {
	return r.saveExchangeWithBody(rawURL, "GET", nil, resp, body)
}

func (r *Runner) saveExchangeWithBody(rawURL, method string, reqBody []byte, resp *http.Response, respBody []byte) (string, string) {
	reqID := core.NewID("req")
	respID := core.NewID("resp")
	now := core.TimestampNow()
	u, _ := url.Parse(rawURL)
	path := "/"
	host := ""
	port := 80
	scheme := "http"
	if u != nil {
		path = u.Path
		if path == "" {
			path = "/"
		}
		host = u.Hostname()
		scheme = u.Scheme
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &port)
		} else if scheme == "https" {
			port = 443
		}
	}
	headers := []models.Header{
		{Name: "User-Agent", Value: "AgentBurp-Crawler/0.1"},
	}
	for _, s := range r.session {
		headers = append(headers, s)
	}
	headersJSON, _ := json.Marshal(headers)

	r.db.Conn().Exec(`
		INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
			query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
		VALUES (?, ?, 'crawler', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reqID, r.projectID, method, rawURL, host, port, scheme, path,
		queryOf(rawURL), string(headersJSON), reqBody, hashBytes(reqBody),
		r.opts.SessionID, r.jobID, now,
	)

	respHeaders := make([]models.Header, 0, len(resp.Header))
	for k, vals := range resp.Header {
		for _, v := range vals {
			respHeaders = append(respHeaders, models.Header{Name: k, Value: v})
		}
	}
	respHeadersJSON, _ := json.Marshal(respHeaders)
	ct := resp.Header.Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	r.db.Conn().Exec(`
		INSERT INTO responses (id, request_id, status_code, reason, headers_json, body_blob,
			body_hash, content_type, length_bytes, time_ms, created_at)
		VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?)`,
		respID, reqID, resp.StatusCode, string(respHeadersJSON), respBody,
		hashBytes(respBody), ct, len(respBody), 0, now,
	)

	hdr := http.Header{}
	for _, h := range headers {
		hdr.Set(h.Name, h.Value)
	}
	agentctx.ExtractEndpoint(r.db.Conn(), r.projectID, reqID, host, method, path, queryOf(rawURL), hdr, reqBody)
	agentctx.UpdateEndpointResponse(r.db.Conn(), reqID, resp.StatusCode, ct)
	return reqID, respID
}

func queryOf(rawURL string) string {
	if i := strings.IndexByte(rawURL, '?'); i != -1 {
		return rawURL[i+1:]
	}
	return ""
}

func isDestructiveURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, marker := range []string{
		"logout", "logoff", "signout", "sign-off", "sign_out",
		"endsession", "end-session", "session/end", "session/delete",
		"kill-session", "destroy", "invalidate-session", "revoke-session",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hashBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
