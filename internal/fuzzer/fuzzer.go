package fuzzer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	agentctx "github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/httpclient"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/scope"
)

type JobConfig struct {
	RequestID  string       `json:"request_id"`
	AttackType string       `json:"attack_type"`
	Positions  []string     `json:"positions"`
	SetIndexes []int        `json:"set_indexes,omitempty"`
	Payloads   []PayloadSet `json:"payloads"`
	Filters    Filters      `json:"filters"`
	SessionID  string       `json:"session_id,omitempty"`
}

type Runner struct {
	db          *core.DB
	conn        *sql.DB
	projectID   string
	jobID       string
	store       *core.JobStore
	cfg         JobConfig
	base        *Request
	positions   []*Position
	sets        [][]string
	filters     Filters
	client      *httpclient.Client
	audit       *scope.AuditLogger
	session     []models.Header
	concurrency int
	baseline    *Baseline
}

func NewRunner(db *core.DB, proj *core.Project, jobID string, concurrency, rate int) (*Runner, error) {
	store := core.NewJobStore(db)
	job, err := store.Get(jobID)
	if err != nil {
		return nil, err
	}
	if job.Type != "fuzz" {
		return nil, fmt.Errorf("job %s is type %q, not fuzz", jobID, job.Type)
	}

	raw, err := json.Marshal(job.Config)
	if err != nil {
		return nil, err
	}
	var cfg JobConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse fuzz job config: %w", err)
	}
	if cfg.RequestID == "" {
		return nil, fmt.Errorf("fuzz job has no base request — recreate with: fuzz create --request <req_id>")
	}
	attack, err := ParseAttackType(cfg.AttackType)
	if err != nil {
		return nil, err
	}
	if cfg.SessionID == "" {
		cfg.SessionID = auth.ActiveSessionID(proj.Name)
	}

	var method, url, headersJSON, queryStr string
	var body []byte
	err = db.Conn().QueryRow(`
		SELECT method, url, headers_json, body_blob, query_string FROM requests WHERE id = ?`, cfg.RequestID,
	).Scan(&method, &url, &headersJSON, &body, &queryStr)
	if err != nil {
		return nil, fmt.Errorf("base request %s not found", cfg.RequestID)
	}
	if queryStr != "" && !strings.Contains(url, "?") {
		url = url + "?" + queryStr
	}
	var headers []models.Header
	json.Unmarshal([]byte(headersJSON), &headers)
	base := &Request{Method: method, URL: url, Body: body}
	for _, h := range headers {
		base.Headers = append(base.Headers, h.Name+": "+h.Value)
	}

	var positions []*Position
	var sets [][]string
	for i, loc := range cfg.Positions {
		p, err := ParsePosition(loc)
		if err != nil {
			return nil, err
		}
		positions = append(positions, p)
		si := 0
		if i < len(cfg.SetIndexes) {
			si = cfg.SetIndexes[i]
		}
		if si < len(cfg.Payloads) {
			sets = append(sets, cfg.Payloads[si].Values)
		} else {
			sets = append(sets, nil)
		}
	}
	hasPayloads := false
	for _, s := range sets {
		if len(s) > 0 {
			hasPayloads = true
			break
		}
	}
	if !hasPayloads {
		return nil, fmt.Errorf("job has no payloads — add one with: fuzz payload wordlist|numbers|mutations <job_id>")
	}
	if _, err := Combos(positions, sets, attack); err != nil {
		return nil, err
	}

	var session []models.Header
	if cfg.SessionID != "" {
		sess, err := auth.NewSessionStore(db, proj.ID).Get(cfg.SessionID)
		if err == nil {
			session = auth.NewSessionStore(db, proj.ID).ApplyToRequest(sess, headers)
		}
	}

	if concurrency <= 0 {
		concurrency = 10
	}

	return &Runner{
		db:          db,
		conn:        db.Conn(),
		projectID:   proj.ID,
		jobID:       jobID,
		store:       store,
		cfg:         cfg,
		base:        base,
		positions:   positions,
		sets:        sets,
		filters:     cfg.Filters,
		client:      httpclient.New(httpclient.Options{Timeout: 30 * time.Second, FollowRedirects: true, RatePerSec: rate}),
		audit:       scope.NewAuditLogger(db, proj.ID),
		session:     session,
		concurrency: concurrency,
	}, nil
}

func (r *Runner) PlanCount() (int, error) {
	return ComboCount(r.positions, r.sets, AttackType(r.cfg.AttackType))
}

func (r *Runner) Positions() []*Position  { return r.positions }
func (r *Runner) PayloadSets() [][]string { return r.sets }
func (r *Runner) AttackType() AttackType  { return AttackType(r.cfg.AttackType) }
func (r *Runner) SessionID() string       { return r.cfg.SessionID }

func (r *Runner) Run(ctx context.Context) error {
	comboCount, err := r.PlanCount()
	if err != nil {
		r.store.MarkFailed(r.jobID, err.Error())
		return err
	}
	if err := r.store.MarkRunning(r.jobID); err != nil {
		return err
	}

	if br, _ := r.sendOne(ctx, map[string]string{}); br != nil {
		r.baseline = &Baseline{Status: br.Status, Length: br.Length, TimeMS: br.TimeMS, Text: br.Text, Artifact: br.Artifact}
	}

	combos, err := Combos(r.positions, r.sets, AttackType(r.cfg.AttackType))
	if err != nil {
		r.store.MarkFailed(r.jobID, err.Error())
		return err
	}

	var (
		wg        sync.WaitGroup
		sent      int64
		succeeded int64
		blocked   int64
		anomalies int64
		skipped   int64
		mu        sync.Mutex
		statusCnt = map[int]int64{}
	)
	sem := make(chan struct{}, r.concurrency)

loop:
	for i, vec := range combos {
		select {
		case <-ctx.Done():
			skipped = int64(len(combos) - i)
			break loop
		default:
		}
		if r.store.IsCancelled(r.jobID) {
			skipped = int64(len(combos) - i)
			break loop
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(vec []string) {
			defer wg.Done()
			defer func() { <-sem }()
			payloads := map[string]string{}
			for j, p := range r.positions {
				if vec[j] != "" {
					payloads[p.Location] = vec[j]
				}
			}
			res, err := r.sendOne(ctx, payloads)
			if err != nil {
				if strings.Contains(err.Error(), "scope") {
					atomic.AddInt64(&blocked, 1)
				}
				return
			}
			atomic.AddInt64(&sent, 1)
			if res == nil {
				return
			}
			atomic.AddInt64(&succeeded, 1)
			mu.Lock()
			statusCnt[res.Status]++
			if res.Anomaly {
				atomic.AddInt64(&anomalies, 1)
			}
			mu.Unlock()
		}(vec)
	}
	wg.Wait()

	summary := map[string]interface{}{
		"total_planned": comboCount,
		"sent":          sent,
		"succeeded":     succeeded,
		"anomalies":     anomalies,
		"blocked":       blocked,
		"skipped":       skipped,
		"status_counts": statusCnt,
		"attack_type":   string(r.cfg.AttackType),
		"positions":     len(r.positions),
		"payload_sets":  len(r.sets),
	}
	if r.baseline != nil {
		summary["baseline"] = map[string]interface{}{
			"status":  r.baseline.Status,
			"length":  r.baseline.Length,
			"time_ms": r.baseline.TimeMS,
		}
	}
	if blocked > 0 {
		summary["note"] = fmt.Sprintf("%d requests blocked by scope rules", blocked)
	}
	return r.store.MarkDone(r.jobID, summary)
}

type Baseline struct {
	Status   int
	Length   int
	TimeMS   int64
	Text     string
	Artifact string
}

type sendResult struct {
	Status        int
	Length        int
	TimeMS        int64
	Text          string
	Artifact      string
	Anomaly       bool
	AnomalyReason string
}

func (r *Runner) sendOne(ctx context.Context, payloads map[string]string) (*sendResult, error) {
	req, err := Apply(r.base, r.positions, payloads)
	if err != nil {
		return nil, err
	}

	engine, err := scope.NewEngine(r.db, r.projectID)
	if err != nil {
		return nil, err
	}
	if !engine.IsInScope(req.URL) {
		r.audit.LogScopeViolation(req.URL, "out of scope")
		return nil, fmt.Errorf("scope violation: %s", req.URL)
	}

	headerMap := map[string]string{}
	for _, h := range req.Headers {
		name, v, _ := strings.Cut(h, ":")
		headerMap[strings.TrimSpace(name)] = strings.TrimSpace(v)
	}
	for _, s := range r.session {
		headerMap[s.Name] = s.Value
	}

	start := time.Now()
	resp, body, err := r.client.Do(ctx, req.Method, req.URL, headerMap, req.Body)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start).Milliseconds()

	reqID := core.NewID("req")
	respID := core.NewID("resp")
	now := core.TimestampNow()
	reqHeaders := make([]models.Header, 0, len(headerMap))
	for k, v := range headerMap {
		reqHeaders = append(reqHeaders, models.Header{Name: k, Value: v})
	}
	reqHeadersJSON, _ := json.Marshal(reqHeaders)

	u, _ := url.Parse(req.URL)
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

	r.conn.Exec(`
		INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
			query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
		VALUES (?, ?, 'fuzzer', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reqID, r.projectID, req.Method, req.URL, host, port, scheme, path,
		queryOf(req.URL), string(reqHeadersJSON), req.Body, hashBytes(req.Body),
		r.cfg.SessionID, r.jobID, now,
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
	r.conn.Exec(`
		INSERT INTO responses (id, request_id, status_code, reason, headers_json, body_blob,
			body_hash, content_type, length_bytes, time_ms, created_at)
		VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?)`,
		respID, reqID, resp.StatusCode, string(respHeadersJSON), body,
		hashBytes(body), ct, len(body), elapsed, now,
	)

	hdr := http.Header{}
	for k, v := range headerMap {
		hdr.Set(k, v)
	}
	agentctx.ExtractEndpoint(r.conn, r.projectID, reqID, host, req.Method, path, queryOf(req.URL), hdr, req.Body)
	agentctx.UpdateEndpointResponse(r.conn, reqID, resp.StatusCode, ct)
	r.audit.LogRequestSent(reqID, "fuzzer")

	anomaly, reason := false, ""
	if !r.filters.Empty() {
		if matched, why := r.filters.Match(resp.StatusCode, len(body), body); matched {
			anomaly, reason = true, "filter: "+why
		}
	} else {
		text := visibleText(body)
		reason = r.deviation(resp.StatusCode, len(body), text, elapsed)
		if reason == "" {
			reason = r.authBypassSignal(payloads, body, resp)
		}
		if reason != "" {
			anomaly = true
		}
	}

	payloadJSON, _ := json.Marshal(payloads)
	frID := core.NewID("fr")
	r.conn.Exec(`
		INSERT INTO fuzz_results (id, job_id, request_id, response_id, payload_json, anomaly, anomaly_reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		frID, r.jobID, reqID, respID, string(payloadJSON), boolInt(anomaly), reason, now,
	)

	return &sendResult{
		Status:        resp.StatusCode,
		Length:        len(body),
		TimeMS:        elapsed,
		Text:          visibleText(body),
		Artifact:      authArtifact(body, resp.Header),
		Anomaly:       anomaly,
		AnomalyReason: reason,
	}, nil
}

func (r *Runner) authBypassSignal(payloads map[string]string, body []byte, resp *http.Response) string {
	b := r.baseline
	if b == nil || b.Artifact == "" {
		return ""
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
		return ""
	}
	if b.Status == 401 || b.Status == 403 || b.Status == 429 {
		return ""
	}
	artifact := authArtifact(body, resp.Header)
	if artifact == "" || artifact == b.Artifact {
		return ""
	}
	modified := false
	for _, p := range r.positions {
		orig := originalValue(r.base, p)
		for _, v := range payloads {
			if v != "" && v != orig {
				modified = true
			}
		}
	}
	if !modified {
		return ""
	}
	if !strings.Contains(artifact, ".") && r.base.Method != "POST" && r.base.Method != "PUT" {
		return ""
	}
	conf := "medium"
	if injectionLike(payloads) {
		conf = "high"
	}
	reason := fmt.Sprintf("authentication artifact issued for modified input (confidence %s): baseline artifact %q differs from %q — possible authentication bypass", conf, shortArtifact(b.Artifact), shortArtifact(artifact))
	return reason
}

var jwtArtifactRx = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}`)

func authArtifact(body []byte, hdr http.Header) string {
	if m := jwtArtifactRx.Find(body); m != nil {
		return string(m)
	}
	if j := strings.TrimSpace(string(body)); len(j) > 0 && (strings.HasPrefix(j, "{") || strings.HasPrefix(j, "[")) {
		var obj map[string]interface{}
		if json.Unmarshal([]byte(j), &obj) == nil {
			if v := findTokenValue(obj); v != "" {
				return v
			}
		}
	}
	for _, raw := range hdr.Values("Set-Cookie") {
		name, _, _ := strings.Cut(raw, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if strings.Contains(name, "session") || strings.Contains(name, "token") || strings.Contains(name, "auth") {
			return strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
		}
	}
	return ""
}

func findTokenValue(obj map[string]interface{}) string {
	tokenKeys := []string{"access_token", "id_token", "refresh_token", "token", "jwt", "api_key", "apikey", "session_id", "csrf_token"}
	for _, tk := range tokenKeys {
		for k, v := range obj {
			if strings.EqualFold(k, tk) {
				if s, ok := v.(string); ok && s != "" && s != "null" {
					return s
				}
			}
		}
	}
	for _, v := range obj {
		if sub, ok := v.(map[string]interface{}); ok {
			if s := findTokenValue(sub); s != "" {
				return s
			}
		}
	}
	return ""
}

func originalValue(base *Request, p *Position) string {
	kind, name, _ := strings.Cut(p.Location, ".")
	if name == "" {
		return ""
	}
	if kind == "query" {
		if u, err := url.Parse(base.URL); err == nil {
			return u.Query().Get(name)
		}
		return ""
	}
	if kind == "body" {
		trimmed := strings.TrimSpace(string(base.Body))
		if strings.HasPrefix(trimmed, "{") {
			var obj map[string]interface{}
			if json.Unmarshal(base.Body, &obj) == nil {
				if s, ok := obj[name].(string); ok {
					return s
				}
				return ""
			}
		} else if strings.Contains(trimmed, "=") {
			if vals, err := url.ParseQuery(trimmed); err == nil {
				return vals.Get(name)
			}
		}
	}
	return ""
}

func injectionLike(payloads map[string]string) bool {
	for _, v := range payloads {
		lower := strings.ToLower(v)
		if strings.ContainsAny(lower, "'\"<>") || strings.Contains(lower, "--") ||
			strings.Contains(lower, " union ") || strings.Contains(lower, " or ") ||
			strings.Contains(lower, " and ") || strings.Contains(lower, " sleep") ||
			strings.Contains(lower, " select ") {
			return true
		}
	}
	return false
}

func shortArtifact(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:21] + "..."
}

func (r *Runner) deviation(status int, length int, text string, timeMS int64) string {
	b := r.baseline
	if b != nil && b.Status != 0 && b.Status != status {
		return fmt.Sprintf("status changed: baseline %d -> %d", b.Status, status)
	}
	if b != nil && b.Length > 0 {
		ratio := float64(length) / float64(b.Length)
		if ratio > 2 {
			return fmt.Sprintf("response length grew %dx (%d -> %d bytes)", int(ratio), b.Length, length)
		}
		if ratio < 0.5 {
			return fmt.Sprintf("response length shrank to %d bytes (baseline %d)", length, b.Length)
		}
	}
	if b != nil && b.Text != "" && text != "" {
		if changed, total := textChangeRatio(b.Text, text); total >= 20 && changed >= 6 && float64(changed)/float64(total) >= 0.01 {
			return fmt.Sprintf("visible text changed (%d of %d words differ from baseline)", changed, total)
		}
	}
	if status >= 500 {
		return fmt.Sprintf("server error status %d", status)
	}
	if timeMS > 5000 {
		return fmt.Sprintf("slow response (%dms)", timeMS)
	}
	return ""
}

func visibleText(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	re := regexp.MustCompile(`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>|<[^>]*>`)
	text := re.ReplaceAllString(string(body), " ")
	text = strings.Join(strings.Fields(text), " ")
	text = regexp.MustCompile(`[0-9]+`).ReplaceAllString(text, "")
	return text
}

func textChangeRatio(a, b string) (changed, total int) {
	wa, wb := strings.Fields(a), strings.Fields(b)
	if len(wa) == 0 || len(wb) == 0 {
		return 0, 0
	}
	m, n := len(wa), len(wb)
	if m > 4000 {
		wa = wa[:4000]
		m = 4000
	}
	if n > 4000 {
		wb = wb[:4000]
		n = 4000
	}
	prev := make([]int, n+1)
	cur := make([]int, n+1)
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if wa[i-1] == wb[j-1] {
				cur[j] = prev[j-1] + 1
			} else if prev[j] >= cur[j-1] {
				cur[j] = prev[j]
			} else {
				cur[j] = cur[j-1]
			}
		}
		prev, cur = cur, prev
	}
	lcs := prev[n]
	changed = m + n - 2*lcs
	total = m
	if n < total {
		total = n
	}
	return changed, total
}

func queryOf(rawURL string) string {
	if i := strings.IndexByte(rawURL, '?'); i != -1 {
		return rawURL[i+1:]
	}
	return ""
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
