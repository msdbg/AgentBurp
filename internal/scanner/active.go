package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/httpclient"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/scope"
)

// Probe is a single active-scan test performed against one endpoint.
type Probe struct {
	Name       string // reflected-xss | sqli-error | path-traversal | idor-signal | auth-bypass | stored-xss | nosql-injection | jwt-alg-none | jwt-hs256-confusion | admin-authz
	Payload    string // injected value, if any
	Position   string // where it was injected, e.g. query.id | body.field
	RequestID  string // stored probe exchange
	ResponseID string
	Status     int
	Length     int
	DurationMS int64
	Result     string // signal text, empty = no issue
	Confidence string
	Severity   string
	Extra      map[string]string `json:"extra,omitempty"`
}

// ActiveOptions configures an active scan run.
type ActiveOptions struct {
	EndpointID  string
	Rate        int
	Concurrency int
}

// RunActive probes one endpoint with safe, non-destructive checks.
// Probe requests are scope-enforced and rate-limited, and each probe
// exchange is persisted so findings link to reproducible evidence.
func RunActive(ctx context.Context, db *core.DB, proj *core.Project, jobID string, opts ActiveOptions) (*ScanSummary, error) {
	store := core.NewJobStore(db)
	if err := store.MarkRunning(jobID); err != nil {
		return nil, err
	}
	start := time.Now()

	findings := NewFindingsStore(db, proj.ID)
	summary := &ScanSummary{
		Mode:           "active",
		BySeverity:     map[string]int{},
		ByCheck:        map[string]int{},
		SkippedReasons: map[string]int{},
	}

	base, err := loadEndpointRequest(db, proj, opts.EndpointID)
	if err != nil {
		store.MarkFailed(jobID, err.Error())
		return nil, err
	}

	client := httpclient.New(httpclient.Options{
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		RatePerSec:      opts.Rate,
	})
	engine, err := scope.NewEngine(db, proj.ID)
	if err != nil {
		return nil, err
	}
	audit := scope.NewAuditLogger(db, proj.ID)

	probes := []*Probe{}

	// 1. Reflected input + SQLi error probes against each parameter.
	for _, pos := range collectParamPositions(db, base) {
		select {
		case <-ctx.Done():
			summary.Note = "cancelled"
			return summary, nil
		default:
		}
		if store.IsCancelled(jobID) {
			summary.Note = "cancelled"
			return summary, nil
		}

		xssProbe, skip := runProbe(ctx, client, engine, audit, db, proj, base, pos, "abz99xssmarker", opts.Rate)
		if xssProbe != nil {
			summary.ProbesSent++
			probes = append(probes, xssProbe)
			if xssProbe.Result != "" {
				summary.Scanned++
				saveActiveFinding(findings, base, xssProbe)
				summary.NewFindings++
				summary.BySeverity[xssProbe.Severity]++
				summary.ByCheck[xssProbe.Name]++
			}
		} else if skip != "" {
			summary.ProbesSkipped++
			summary.SkippedReasons[skip]++
		}

		sqliProbe, skip := runProbe(ctx, client, engine, audit, db, proj, base, pos, "'", opts.Rate)
		if sqliProbe != nil {
			summary.ProbesSent++
			probes = append(probes, sqliProbe)
			if sqliProbe.Result != "" {
				summary.Scanned++
				saveActiveFinding(findings, base, sqliProbe)
				summary.NewFindings++
				summary.BySeverity[sqliProbe.Severity]++
				summary.ByCheck[sqliProbe.Name]++
			}
		} else if skip != "" {
			summary.ProbesSkipped++
			summary.SkippedReasons[skip]++
		}
	}

	// 2. IDOR signal: numeric path IDs respond to incremented values.
	if idor := probeIDOR(ctx, client, engine, audit, db, proj, base, opts.Rate); idor != nil {
		summary.ProbesSent++
		probes = append(probes, idor)
		if idor.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, idor)
			summary.NewFindings++
			summary.BySeverity[idor.Severity]++
			summary.ByCheck[idor.Name]++
		}
	}

	// 3. Auth bypass: repeat the request without credentials.
	if bypass := probeAuthBypass(ctx, client, engine, audit, db, proj, base, opts.Rate); bypass != nil {
		summary.ProbesSent++
		probes = append(probes, bypass)
		if bypass.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, bypass)
			summary.NewFindings++
			summary.BySeverity[bypass.Severity]++
			summary.ByCheck[bypass.Name]++
		}
	}

	// 4. Stored XSS: POST/PUT input that persists into a subsequent GET.
	if stored := probeStoredXSS(ctx, client, engine, audit, db, proj, base, opts.Rate); stored != nil {
		summary.ProbesSent++
		probes = append(probes, stored)
		if stored.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, stored)
			summary.NewFindings++
			summary.BySeverity[stored.Severity]++
			summary.ByCheck[stored.Name]++
		}
	}

	// 5. Path traversal / LFI: file inclusion parameters that resolve outside the web root.
	if trav := probeTraversal(ctx, client, engine, audit, db, proj, base, opts.Rate); trav != nil {
		summary.ProbesSent++
		probes = append(probes, trav)
		if trav.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, trav)
			summary.NewFindings++
			summary.BySeverity[trav.Severity]++
			summary.ByCheck[trav.Name]++
		}
	}

	// 6. NoSQL injection: operator payloads in JSON auth fields cause the
	// server to match a user (state flip from "not found" to "found").
	if nosql := probeNoSQLi(ctx, client, engine, audit, db, proj, base, opts.Rate); nosql != nil {
		summary.ProbesSent++
		probes = append(probes, nosql)
		if nosql.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, nosql)
			summary.NewFindings++
			summary.BySeverity[nosql.Severity]++
			summary.ByCheck[nosql.Name]++
		}
	}

	// 7. JWT alg=none: forged unsigned tokens accepted by the server.
	if jwtProbe := probeJWTAlgNone(ctx, client, engine, audit, db, proj, base, opts.Rate); jwtProbe != nil {
		summary.ProbesSent++
		probes = append(probes, jwtProbe)
		if jwtProbe.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, jwtProbe)
			summary.NewFindings++
			summary.BySeverity[jwtProbe.Severity]++
			summary.ByCheck[jwtProbe.Name]++
		}
	}

	// 8. JWT key confusion: HS256 tokens signed with the leaked public key.
	if keyProbe := probeJWTKeyConfusion(ctx, client, engine, audit, db, proj, base, opts.Rate); keyProbe != nil {
		summary.ProbesSent++
		probes = append(probes, keyProbe)
		if keyProbe.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, keyProbe)
			summary.NewFindings++
			summary.BySeverity[keyProbe.Severity]++
			summary.ByCheck[keyProbe.Name]++
		}
	}

	// 9. Admin authorization: admin-sensitive endpoints reachable with a
	// user-level token (broken function-level authorization).
	if adminProbe := probeAdminAuthz(ctx, client, engine, audit, db, proj, base, opts.Rate); adminProbe != nil {
		summary.ProbesSent++
		probes = append(probes, adminProbe)
		if adminProbe.Result != "" {
			summary.Scanned++
			saveActiveFinding(findings, base, adminProbe)
			summary.NewFindings++
			summary.BySeverity[adminProbe.Severity]++
			summary.ByCheck[adminProbe.Name]++
		}
	}

	summary.DurationMS = time.Since(start).Milliseconds()
	counts, _ := findings.Counts()
	for _, n := range counts {
		summary.TotalFindings += n
	}
	note := ""
	if summary.NewFindings == 0 {
		note = "no signals detected"
	}
	if summary.ProbesSkipped > 0 {
		reasons := make([]string, 0, len(summary.SkippedReasons))
		for r, c := range summary.SkippedReasons {
			reasons = append(reasons, fmt.Sprintf("%s x%d", r, c))
		}
		sort.Strings(reasons)
		if note != "" {
			note += "; "
		}
		note += fmt.Sprintf("%d probes skipped (%s)", summary.ProbesSkipped, strings.Join(reasons, ", "))
	}
	summary.Note = note
	if store.IsCancelled(jobID) {
		return summary, nil
	}
	if err := store.MarkDone(jobID, summaryJSON(summary)); err != nil {
		return nil, err
	}
	return summary, nil
}

// endpointBase is the representative request loaded for an endpoint.
type endpointBase struct {
	EndpointID   string
	Method       string
	URL          string
	Headers      []models.Header
	Body         []byte
	SessionID    string
	PathTemplate string
}

// loadEndpointRequest finds the most recent stored request for an endpoint.
func loadEndpointRequest(db *core.DB, proj *core.Project, endpointID string) (*endpointBase, error) {
	var host, method, template string
	err := db.Conn().QueryRow(
		`SELECT host, method, path_template FROM endpoints WHERE id = ? AND project_id = ?`,
		endpointID, proj.ID,
	).Scan(&host, &method, &template)
	if err != nil {
		return nil, errf("endpoint %q not found", endpointID)
	}

	var reqID, rawURL, headersJSON string
	var body []byte
	var sessionID sql.NullString
	err = db.Conn().QueryRow(`
		SELECT id, url, headers_json, body_blob, session_id FROM requests
		WHERE project_id = ? AND endpoint_id = ?
		ORDER BY created_at DESC LIMIT 1`, proj.ID, endpointID,
	).Scan(&reqID, &rawURL, &headersJSON, &body, &sessionID)
	if err != nil {
		return nil, errf("no stored request for endpoint %q — capture or import traffic first", endpointID)
	}

	base := &endpointBase{
		EndpointID:   endpointID,
		Method:       method,
		URL:          rawURL,
		Body:         body,
		PathTemplate: template,
		SessionID:    sessionID.String,
	}
	json.Unmarshal([]byte(headersJSON), &base.Headers)

	// Refresh the session cookie from the session record attached to the
	// request. History can hold stale cookies (e.g. after logout), and the
	// active session may have rotated — probes must carry a live credential.
	// Fall back to the project's active session when the request's own
	// session record is gone (e.g. replaced by a re-login).
	sessID := base.SessionID
	if sessID != "" {
		var cookiesJSON string
		if err := db.Conn().QueryRow(
			`SELECT cookies_json FROM sessions WHERE id = ? AND project_id = ?`,
			sessID, proj.ID,
		).Scan(&cookiesJSON); err == nil && cookiesJSON != "" && cookiesJSON != "null" {
			refreshCookie(base, cookiesJSON)
		} else {
			sessID = ""
		}
	}
	if sessID == "" {
		if active := auth.ActiveSessionID(proj.Name); active != "" {
			var cookiesJSON string
			if err := db.Conn().QueryRow(
				`SELECT cookies_json FROM sessions WHERE id = ? AND project_id = ?`,
				active, proj.ID,
			).Scan(&cookiesJSON); err == nil && cookiesJSON != "" && cookiesJSON != "null" {
				refreshCookie(base, cookiesJSON)
			}
		}
	}
	return base, nil
}

// refreshCookie replaces (or adds) the Cookie header with session cookies.
func refreshCookie(base *endpointBase, cookiesJSON string) {
	var entries []models.CookieEntry
	if json.Unmarshal([]byte(cookiesJSON), &entries) != nil || len(entries) == 0 {
		return
	}
	parts := make([]string, 0, len(entries))
	for _, ce := range entries {
		parts = append(parts, ce.Name+"="+ce.Value)
	}
	cookie := strings.Join(parts, "; ")
	for i := range base.Headers {
		if strings.EqualFold(base.Headers[i].Name, "Cookie") {
			base.Headers[i].Value = cookie
			return
		}
	}
	base.Headers = append(base.Headers, models.Header{Name: "Cookie", Value: cookie})
}

// paramPositions enumerates injectable parameters (query + JSON body + form body).
func (b *endpointBase) paramPositions() []string {
	var out []string
	if u, err := url.Parse(b.URL); err == nil {
		for k := range u.Query() {
			out = append(out, "query."+k)
		}
	}
	if len(b.Body) > 0 {
		trimmed := strings.TrimSpace(string(b.Body))
		if strings.HasPrefix(trimmed, "{") {
			var obj map[string]interface{}
			if json.Unmarshal(b.Body, &obj) == nil {
				for k := range obj {
					out = append(out, "body."+k)
				}
			}
		} else if strings.Contains(trimmed, "=") {
			vals, _ := url.ParseQuery(trimmed)
			for k := range vals {
				out = append(out, "body."+k)
			}
		}
	}
	return out
}

// collectParamPositions merges the base request's own parameters with all
// historically observed parameters for the endpoint. This ensures a probe is
// still sent for e.g. tfSearch on /Search.asp even when the representative
// request chosen as the base happens to be the bare path without a query.
func collectParamPositions(db *core.DB, b *endpointBase) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range b.paramPositions() {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	rows, err := db.Conn().Query(`SELECT name, location FROM parameters WHERE endpoint_id = ?`, b.EndpointID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name, loc string
		if rows.Scan(&name, &loc) != nil {
			continue
		}
		key := loc + "." + name
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// probeResult analyzes one probe response against its baseline.
type probeResult struct {
	status int
	body   []byte
}

// runProbe injects a payload at a position, sends the request, and
// evaluates reflected-XSS or SQLi-error signals. Returns nil with a
// non-empty reason when the probe could not be executed.
func runProbe(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, position, payload string, rate int) (*Probe, string) {

	reqURL, reqBody, ok := applyPosition(base, position, payload)
	if !ok {
		return nil, "no injectable position"
	}
	if !engine.IsInScope(reqURL) {
		audit.LogScopeViolation(reqURL, "out of scope")
		return nil, "out of scope"
	}

	probe := &Probe{
		Name:     "reflected-xss",
		Payload:  payload,
		Position: position,
		Extra:    map[string]string{},
	}
	if payload == "'" {
		probe.Name = "sqli-error"
	}

	headerMap := base.headerMap()
	start := time.Now()
	resp, body, err := client.Do(ctx, base.Method, reqURL, headerMap, reqBody)
	if err != nil {
		return nil, "request failed"
	}
	probe.DurationMS = time.Since(start).Milliseconds()
	probe.Status = resp.StatusCode
	probe.Length = len(body)
	probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, reqURL, headerMap, reqBody, resp, body, probe.Name)

	// Evaluation.
	if probe.Name == "reflected-xss" && payload != "" {
		// Case-insensitive: some backends (e.g. HSQLDB error output)
		// normalize injected values to uppercase while still echoing them.
		if strings.Contains(strings.ToLower(string(body)), payload) {
			probe.Result = fmt.Sprintf("parameter %s reflects the value %q unencoded in the response", position, payload)
			probe.Confidence = "medium"
			probe.Severity = "low"
		}
	}
	if probe.Name == "sqli-error" {
		if reason := sqliErrorIn(body); reason != "" {
			probe.Result = fmt.Sprintf("parameter %s triggered SQL error signal: %s", position, reason)
			probe.Confidence = "high"
			probe.Severity = "medium"
		} else if probe.Status >= 500 && strings.Contains(strings.ToLower(string(body)), "500 - internal server error") {
			// Generic 500 without verbose DB error — IIS customErrors hides
			// details (as on testasp.vulnweb.com). Verify with a benign
			// baseline: if "1" returns 200, the single-quote broke SQL.
			benignURL, benignBodyReq, ok := applyPosition(base, position, "1")
			if ok && engine.IsInScope(benignURL) {
				bResp, bBody, bErr := client.Do(ctx, base.Method, benignURL, headerMap, benignBodyReq)
				if bErr == nil {
					_, _ = saveProbeExchange(db, proj.ID, base, benignURL, headerMap, benignBodyReq, bResp, bBody, "sqli-baseline")
					if bResp.StatusCode == 200 && !strings.Contains(strings.ToLower(string(bBody)), "500 - internal server error") {
						probe.Result = fmt.Sprintf("parameter %s triggers generic 500 Internal Server Error with single-quote while benign value returns 200 — likely SQL injection (verbose errors disabled, IIS customErrors)", position)
						probe.Confidence = "medium"
						probe.Severity = "medium"
					}
				}
			}
		}
	}
	return probe, ""
}

var sqliErrorRx = regexp.MustCompile(`(?i)(SQL syntax|syntax error at or near|near "[^"]+": syntax|mysql_fetch|ORA-\d{4,5}|SQLiteException|SQLSTATE|Unclosed quotation mark|you have an error in your SQL|PostgreSQL.*ERROR|psycopg|sqlite3\.OperationalError|incorrect syntax near|malformed string|unexpected token|Column not found|error in statement|org\.hsqldb)`)

func sqliErrorIn(body []byte) string {
	m := sqliErrorRx.FindStringSubmatch(string(body))
	if len(m) > 0 {
		return strings.TrimSpace(m[0])
	}
	return ""
}

// probeIDOR checks whether numeric path IDs respond identically to an
// incremented value, indicating weak object authorization.
func probeIDOR(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	id, ok := numericPathID(base.URL)
	if !ok {
		return nil
	}
	alt := fmt.Sprintf("%d", id+1)
	u, err := url.Parse(base.URL)
	if err != nil {
		return nil
	}
	// Replace the LAST path segment only — never digits in host/port/query.
	segs := strings.Split(u.Path, "/")
	segs[len(segs)-1] = alt
	u.Path = strings.Join(segs, "/")
	altURL := u.String()
	if !engine.IsInScope(altURL) {
		audit.LogScopeViolation(altURL, "out of scope")
		return nil
	}

	probe := &Probe{Name: "idor-signal", Payload: alt, Position: "path.id", Extra: map[string]string{}}
	headerMap := base.headerMap()
	resp, body, err := client.Do(ctx, base.Method, altURL, headerMap, base.Body)
	if err != nil {
		return nil
	}
	probe.Status = resp.StatusCode
	probe.Length = len(body)
	probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, altURL, headerMap, base.Body, resp, body, "idor-signal")

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		probe.Result = fmt.Sprintf(
			"path ID %d replaced with %d still returns %d with %d bytes — sequential object IDs appear directly enumerable (verify authorization server-side)",
			id, id+1, resp.StatusCode, len(body))
		probe.Confidence = "low"
		probe.Severity = "info"
	}
	return probe
}

func numericPathID(rawURL string) (int64, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, false
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		var n int64
		if _, err := fmt.Sscanf(segs[i], "%d", &n); err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}

// probeAuthBypass re-sends the request without credentials and compares.
func probeAuthBypass(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	if !engine.IsInScope(base.URL) {
		audit.LogScopeViolation(base.URL, "out of scope")
		return nil
	}

	// Pre-auth endpoints (login, signup, OTP, password recovery, token
	// refresh) are public by design: they answer identically with and
	// without credentials, so the "same response with/without credentials"
	// signal would be a systematic false positive there.
	if preAuthPathRx.MatchString(base.URL) || preAuthPathRx.MatchString(base.PathTemplate) {
		return nil
	}

	// Baseline (authenticated) request.
	authHeaders := base.headerMap()
	baseResp, baseBody, err := client.Do(ctx, base.Method, base.URL, authHeaders, base.Body)
	if err != nil {
		return nil
	}

	// Skip the probe when the baseline itself is an authentication challenge
	// (e.g. scanning the login page) — "200 + login form" is expected there.
	if looksLikeAuthChallenge(baseBody) {
		return nil
	}

	// Unauthenticated probe: drop credentials.
	anonHeaders := map[string]string{}
	for k, v := range authHeaders {
		lower := strings.ToLower(k)
		if lower == "cookie" || lower == "authorization" || lower == "x-api-key" {
			continue
		}
		anonHeaders[k] = v
	}
	anonResp, anonBody, err := client.Do(ctx, base.Method, base.URL, anonHeaders, base.Body)
	if err != nil {
		return nil
	}

	probe := &Probe{Name: "auth-bypass", Position: "headers", Extra: map[string]string{}}
	probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, base.URL, anonHeaders, base.Body, anonResp, anonBody, "auth-bypass")
	probe.Status = anonResp.StatusCode
	probe.Length = len(anonBody)

	// Records for comparison.
	_, _ = saveProbeExchange(db, proj.ID, base, base.URL, authHeaders, base.Body, baseResp, baseBody, "auth-baseline")

	// The unauthenticated response may be an authentication challenge (login
	// form / access denied page) rather than the protected resource. Apps
	// that redirect to a login page and return 200 (e.g. PHP apps) would
	// otherwise produce a false "bypass" signal — a challenge means the
	// endpoint IS protected, just via redirect instead of 401/403.
	sameResponse := len(baseBody) == len(anonBody) && bytes.Equal(baseBody, anonBody)

	switch {
	case baseResp.StatusCode == 401 || baseResp.StatusCode == 403:
		if anonResp.StatusCode == 200 || anonResp.StatusCode == 201 {
			if looksLikeAuthChallenge(anonBody) {
				probe.Extra["note"] = "unauthenticated response is an authentication challenge (login form) — access is enforced via redirect, not a bypass"
				return probe
			}
			probe.Result = fmt.Sprintf(
				"endpoint requires auth (%d with credentials) but returns %d without any credentials — authorization bypass",
				baseResp.StatusCode, anonResp.StatusCode)
			probe.Confidence = "high"
			probe.Severity = "high"
		}
	case baseResp.StatusCode == 200:
		if anonResp.StatusCode == 200 || anonResp.StatusCode == 201 {
			if sameResponse {
				// Identical body with and without credentials: no authorization
				// check on this endpoint. Only signal for sensitive-looking paths.
				if sensitivePathRx.MatchString(base.PathTemplate) || sensitivePathRx.MatchString(base.URL) {
					probe.Result = "endpoint returns an identical 200 response both with and without credentials on a sensitive resource"
					probe.Confidence = "medium"
					probe.Severity = "medium"
				}
				return probe
			}
			if looksLikeAuthChallenge(anonBody) {
				probe.Extra["note"] = "unauthenticated response is an authentication challenge (login form) — not a bypass"
				return probe
			}
			if sensitivePathRx.MatchString(base.PathTemplate) || sensitivePathRx.MatchString(base.URL) {
				probe.Result = "endpoint returns 200 both with and without credentials on a sensitive resource"
				probe.Confidence = "medium"
				probe.Severity = "medium"
			}
		}
	}
	return probe
}

// probeStoredXSS checks whether input persisted via POST/PUT is reflected in
// a subsequent GET of the same resource or its collection (stored XSS).
func probeStoredXSS(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	if base.Method != "POST" && base.Method != "PUT" {
		return nil
	}
	u, err := url.Parse(base.URL)
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(base.Body))
	var bodyObj map[string]interface{}
	if strings.HasPrefix(trimmed, "{") {
		if json.Unmarshal(base.Body, &bodyObj) != nil {
			return nil
		}
	} else if !strings.Contains(trimmed, "=") {
		return nil
	}
	// Inject the marker into the first string-valued body parameter.
	// JSON objects and form-encoded bodies are both supported.
	name := ""
	if len(bodyObj) > 0 {
		for k, v := range bodyObj {
			if s, ok := v.(string); ok && s != "" {
				name = k
				break
			}
		}
	} else if vals, err := url.ParseQuery(trimmed); err == nil {
		for k, vs := range vals {
			if len(vs) > 0 && vs[0] != "" {
				name = k
				break
			}
		}
	}
	if name == "" {
		return nil
	}

	marker := "abzstoredxssmarker"
	reqURL, reqBody, ok := applyPosition(base, "body."+name, marker)
	if !ok || !engine.IsInScope(reqURL) {
		return nil
	}
	headerMap := base.headerMap()
	resp, body, err := client.Do(ctx, base.Method, reqURL, headerMap, reqBody)
	if err != nil {
		return nil
	}
	postReqID, postRespID := saveProbeExchange(db, proj.ID, base, reqURL, headerMap, reqBody, resp, body, "stored-xss-write")
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil // store rejected — nothing persisted to check
	}

	probe := &Probe{Name: "stored-xss", Payload: marker, Position: "body." + name, Extra: map[string]string{}}
	probe.RequestID, probe.ResponseID = postReqID, postRespID
	probe.Status = resp.StatusCode
	probe.Length = len(body)

	// Read back the resource: the same path as GET, then the parent collection.
	candidates := []string{base.URL}
	if segs := strings.Split(strings.Trim(u.Path, "/"), "/"); len(segs) > 1 {
		u2 := *u
		u2.Path = "/" + strings.Join(segs[:len(segs)-1], "/")
		candidates = append(candidates, u2.String())
	}
	for _, c := range candidates {
		if !engine.IsInScope(c) {
			continue
		}
		getResp, getBody, err := client.Do(ctx, http.MethodGet, c, headerMap, nil)
		if err != nil {
			continue
		}
		getReqID, getRespID := saveProbeExchange(db, proj.ID, base, c, headerMap, nil, getResp, getBody, "stored-xss-read")
		if getResp.StatusCode == 200 && strings.Contains(string(getBody), marker) {
			probe.Result = fmt.Sprintf(
				"value %q submitted via %s %s was stored and is reflected unencoded in the response of GET %s — stored XSS (script execution in other users' sessions)",
				marker, base.Method, reqURL, c)
			probe.Confidence = "high"
			probe.Severity = "high"
			probe.RequestID, probe.ResponseID = getReqID, getRespID
			break
		}
	}
	return probe
}

// probeTraversal checks for path traversal / LFI via file inclusion parameters.
// It injects directory traversal payloads into query params that look like
// file paths (item, file, path, template, page, include, etc.) and detects
// a differential: benign value returns 200 while traversal returns 500 or
// reveals file content (e.g. "root:" from /etc/passwd). This catches
// Templatize.asp?item=html/about.html on testasp.vulnweb.com.
func probeTraversal(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	// Only GET query params are typical for LFI; POST bodies rarely include file paths.
	positions := collectParamPositions(db, base)
	var fileParams []string
	for _, pos := range positions {
		if !strings.HasPrefix(pos, "query.") {
			continue
		}
		name := strings.TrimPrefix(pos, "query.")
		lower := strings.ToLower(name)
		// Target file-like params or, if none, try all query params as fallback.
		if strings.Contains(lower, "file") || strings.Contains(lower, "path") || strings.Contains(lower, "item") ||
			strings.Contains(lower, "template") || strings.Contains(lower, "page") || strings.Contains(lower, "include") ||
			strings.Contains(lower, "dir") || strings.Contains(lower, "doc") {
			fileParams = append(fileParams, pos)
		}
	}
	if len(fileParams) == 0 {
		return nil
	}

	payloads := []string{"../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"}
	for _, pos := range fileParams {
		// Baseline: fixed benign value that should return 200. Do not use the
		// base URL's current value — it may be polluted by prior probes (e.g.
		// item=' from sqli) and would give 500, causing the traversal check
		// to be skipped. For Templatize use known good file, else "1".
		benign := "1"
		if strings.EqualFold(strings.TrimPrefix(pos, "query."), "item") {
			benign = "html/about.html"
		}
		benignURL, benignBody, ok := applyPosition(base, pos, benign)
		if !ok || !engine.IsInScope(benignURL) {
			continue
		}
		bResp, bBody, err := client.Do(ctx, base.Method, benignURL, base.headerMap(), benignBody)
		if err != nil {
			continue
		}
		_, _ = saveProbeExchange(db, proj.ID, base, benignURL, base.headerMap(), benignBody, bResp, bBody, "traversal-baseline")
		if bResp.StatusCode != 200 {
			continue
		}
		for _, payload := range payloads {
			reqURL, reqBody, ok := applyPosition(base, pos, payload)
			if !ok || !engine.IsInScope(reqURL) {
				continue
			}
			resp, body, err := client.Do(ctx, base.Method, reqURL, base.headerMap(), reqBody)
			if err != nil {
				continue
			}
			probe := &Probe{Name: "path-traversal", Payload: payload, Position: pos, Extra: map[string]string{}}
			probe.Status = resp.StatusCode
			probe.Length = len(body)
			probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, reqURL, base.headerMap(), reqBody, resp, body, "path-traversal")
			// Oracle 1: traversal reveals Unix passwd content.
			if strings.Contains(string(body), "root:") && strings.Contains(string(body), ":0:0:") {
				probe.Result = fmt.Sprintf("parameter %s with payload %q returned file content containing root: — local file inclusion / path traversal", pos, payload)
				probe.Confidence = "high"
				probe.Severity = "high"
				return probe
			}
			// Oracle 2: generic 500 while baseline 200 — IIS customErrors hides details (testasp).
			if resp.StatusCode >= 500 && strings.Contains(strings.ToLower(string(body)), "500 - internal server error") {
				probe.Result = fmt.Sprintf("parameter %s triggers generic 500 Internal Server Error with traversal payload %q while benign value returns 200 — likely path traversal / LFI (verbose errors disabled)", pos, payload)
				probe.Confidence = "medium"
				probe.Severity = "medium"
				return probe
			}
		}
	}
	return nil
}

// probeNoSQLi checks whether a JSON auth endpoint interprets operator syntax
// (e.g. {"$ne": ""}) in a login field as a MongoDB query instead of a literal
// string. The oracle is a deterministic state flip: a random nonexistent
// username is rejected with a "not found" error, while the same request with
// an operator payload is treated as a query that matches an existing user
// (the server returns a password/credentials error instead).
func probeNoSQLi(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	if base.Method != "POST" && base.Method != "PUT" {
		return nil
	}
	trimmed := strings.TrimSpace(string(base.Body))
	if !strings.HasPrefix(trimmed, "{") {
		return nil // operator injection requires a JSON object body
	}
	var bodyObj map[string]interface{}
	if json.Unmarshal(base.Body, &bodyObj) != nil {
		return nil
	}
	// Identify a credential-like field to target (user/login/name/email).
	name := ""
	for k, v := range bodyObj {
		lk := strings.ToLower(k)
		if s, ok := v.(string); ok && s != "" && (strings.Contains(lk, "user") || strings.Contains(lk, "login") || strings.Contains(lk, "name") || strings.Contains(lk, "email")) {
			name = k
			break
		}
	}
	if name == "" {
		return nil
	}

	// Baseline: a username that cannot exist.
	baselineVal := "abz-nosuch-" + core.NewID("u")[:8]
	obj := make(map[string]interface{}, len(bodyObj)+1)
	for k, v := range bodyObj {
		obj[k] = v
	}
	obj[name] = baselineVal
	baseBody, _ := json.Marshal(obj)

	resp, body, err := client.Do(ctx, base.Method, base.URL, base.headerMap(), baseBody)
	if err != nil {
		return nil
	}
	baselineReqID, baselineRespID := saveProbeExchange(db, proj.ID, base, base.URL, base.headerMap(), baseBody, resp, body, "nosqli-baseline")
	if resp.StatusCode >= 400 {
		return nil // endpoint errors on malformed input — not a useful oracle
	}
	notFound := hasAny(body, notFoundSignals)

	// Injection: same request with an operator payload as the credential field.
	obj[name] = map[string]interface{}{"$ne": ""}
	injBody, _ := json.Marshal(obj)
	resp2, body2, err := client.Do(ctx, base.Method, base.URL, base.headerMap(), injBody)
	if err != nil {
		return nil
	}
	injReqID, injRespID := saveProbeExchange(db, proj.ID, base, base.URL, base.headerMap(), injBody, resp2, body2, "nosqli-inject")
	if resp2.StatusCode >= 400 {
		return nil
	}
	found := hasAny(body2, foundSignals)

	probe := &Probe{Name: "nosql-injection", Payload: `{"$ne":""}`, Position: "body." + name}
	if notFound && found {
		probe.Result = fmt.Sprintf(
			"username field %q is vulnerable to NoSQL injection: a random value is rejected (%q) but operator payload %q is treated as a query that matches an existing user (%q) — authentication bypass and user enumeration",
			name, baselineVal, `{"$ne":""}`, "password/credentials error")
		probe.Confidence = "high"
		probe.Severity = "high"
		probe.RequestID, probe.ResponseID = injReqID, injRespID
		probe.Status = resp2.StatusCode
		probe.Length = len(body2)
	} else {
		probe.RequestID, probe.ResponseID = baselineReqID, baselineRespID
		probe.Status = resp.StatusCode
		probe.Length = len(body)
	}
	return probe
}

// notFoundSignals match error pages that indicate a queried record was not
// found (no user / invalid username / unknown account).
var notFoundSignals = []string{
	"invalid username", "invalid user", "no user", "user not found",
	"unknown user", "does not exist", "not exist", "no such user",
	"account not found", "invalid login",
}

// foundSignals match errors returned when a user record WAS matched but the
// password failed — the tell-tale sign that an injected operator query hit a
// real record.
var foundSignals = []string{
	"invalid password", "incorrect password", "password does not match",
	"wrong password", "invalid credentials", "credentials", "password",
	"bad credentials",
}

// hasAny reports whether the response body contains any of the signals.
func hasAny(body []byte, signals []string) bool {
	low := strings.ToLower(string(body))
	for _, s := range signals {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// probeJWTAlgNone checks whether the server accepts JWTs with alg=none,
// which would let an attacker mint tokens for any identity without a key.
func probeJWTAlgNone(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	bearer := ""
	for _, h := range base.Headers {
		if strings.EqualFold(h.Name, "Authorization") && strings.HasPrefix(h.Value, "Bearer ") {
			bearer = strings.TrimSpace(strings.TrimPrefix(h.Value, "Bearer "))
		}
	}
	if bearer == "" || !strings.Contains(bearer, ".") {
		return nil
	}
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil
	}
	if !engine.IsInScope(base.URL) {
		audit.LogScopeViolation(base.URL, "out of scope")
		return nil
	}

	authHeaders := base.headerMap()
	authResp, _, err := client.Do(ctx, base.Method, base.URL, authHeaders, base.Body)
	if err != nil {
		return nil
	}

	anonHeaders := map[string]string{}
	for k, v := range authHeaders {
		lower := strings.ToLower(k)
		if lower == "cookie" || lower == "authorization" || lower == "x-api-key" {
			continue
		}
		anonHeaders[k] = v
	}
	anonResp, anonBody, err := client.Do(ctx, base.Method, base.URL, anonHeaders, base.Body)
	if err != nil {
		return nil
	}
	// Endpoint serves the same response with and without credentials —
	// no authentication to bypass.
	if anonResp.StatusCode == authResp.StatusCode {
		return nil
	}

	// Forge the alg=none variant: same claims, empty signature.
	noneHeader := base64URLEncode([]byte(`{"alg":"none","typ":"JWT"}`))
	forged := noneHeader + "." + parts[1] + "."
	forgeHeaders := map[string]string{}
	for k, v := range authHeaders {
		forgeHeaders[k] = v
	}
	forgeHeaders["Authorization"] = "Bearer " + forged
	forgeResp, forgeBody, err := client.Do(ctx, base.Method, base.URL, forgeHeaders, base.Body)
	if err != nil {
		return nil
	}

	// Garbage-token oracle: an invalid signature must be rejected for the
	// forged-token result to be meaningful. If the endpoint fails the same
	// way for a random token as for the forged one, the response is not
	// evidence of an accepted signature (e.g. the handler errors before or
	// regardless of token validation).
	garbageHeaders := map[string]string{}
	for k, v := range authHeaders {
		garbageHeaders[k] = v
	}
	garbageHeaders["Authorization"] = "Bearer aaaa.bbbb.cccc"
	garbageResp, garbageBody, err := client.Do(ctx, base.Method, base.URL, garbageHeaders, base.Body)
	if err != nil {
		return nil
	}

	probe := &Probe{Name: "jwt-alg-none", Payload: "alg=none", Position: "header.authorization", Extra: map[string]string{}}
	probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, base.URL, forgeHeaders, base.Body, forgeResp, forgeBody, "jwt-alg-none")
	_, _ = saveProbeExchange(db, proj.ID, base, base.URL, anonHeaders, base.Body, anonResp, anonBody, "jwt-anon-baseline")
	_, _ = saveProbeExchange(db, proj.ID, base, base.URL, garbageHeaders, base.Body, garbageResp, garbageBody, "jwt-garbage-oracle")
	probe.Status = forgeResp.StatusCode
	probe.Length = len(forgeBody)

	if forgeResp.StatusCode == authResp.StatusCode && garbageResp.StatusCode != forgeResp.StatusCode {
		probe.Result = fmt.Sprintf(
			"endpoint returns %d with the real JWT and %d with a forged alg=none token (empty signature, claims copied from the original) while unauthenticated requests receive %d and invalid tokens %d — JWT verification does not enforce the signing algorithm, enabling arbitrary identity forgery",
			authResp.StatusCode, forgeResp.StatusCode, anonResp.StatusCode, garbageResp.StatusCode)
		probe.Confidence = "high"
		probe.Severity = "critical"
	}
	return probe
}

// probeJWTKeyConfusion checks whether the server accepts HS256 tokens
// signed with the RSA public key it publishes (e.g. via JWKS). When a
// verifier mixes up signing and verification keys, an attacker can forge
// tokens for any identity without ever possessing the private key.
func probeJWTKeyConfusion(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	bearer := bearerToken(base.Headers)
	if bearer == "" || !strings.Contains(bearer, ".") {
		return nil
	}
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil
	}
	if !engine.IsInScope(base.URL) {
		audit.LogScopeViolation(base.URL, "out of scope")
		return nil
	}

	authHeaders := base.headerMap()
	authResp, _, err := client.Do(ctx, base.Method, base.URL, authHeaders, base.Body)
	if err != nil {
		return nil
	}

	anonHeaders := map[string]string{}
	for k, v := range authHeaders {
		lower := strings.ToLower(k)
		if lower == "cookie" || lower == "authorization" || lower == "x-api-key" {
			continue
		}
		anonHeaders[k] = v
	}
	anonResp, anonBody, err := client.Do(ctx, base.Method, base.URL, anonHeaders, base.Body)
	if err != nil {
		return nil
	}
	// Endpoint serves the same response with and without credentials —
	// no authentication to bypass.
	if anonResp.StatusCode == authResp.StatusCode {
		return nil
	}

	// Fetch the RSA public key published by the same origin.
	secret, keyURL, err := fetchJWKSPublicKey(ctx, client, base.URL)
	if err != nil || len(secret) == 0 {
		return nil
	}

	// Forge an HS256 token: same claims as the real token, signed with the
	// public key bytes as the HMAC secret.
	sigInput := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	forged := sigInput + "." + base64URLEncode(mac.Sum(nil))

	forgeHeaders := map[string]string{}
	for k, v := range authHeaders {
		forgeHeaders[k] = v
	}
	forgeHeaders["Authorization"] = "Bearer " + forged
	forgeResp, forgeBody, err := client.Do(ctx, base.Method, base.URL, forgeHeaders, base.Body)
	if err != nil {
		return nil
	}

	garbageHeaders := map[string]string{}
	for k, v := range authHeaders {
		garbageHeaders[k] = v
	}
	garbageHeaders["Authorization"] = "Bearer aaaa.bbbb.cccc"
	garbageResp, garbageBody, err := client.Do(ctx, base.Method, base.URL, garbageHeaders, base.Body)
	if err != nil {
		return nil
	}

	probe := &Probe{Name: "jwt-hs256-confusion", Payload: "HS256+pubkey", Position: "header.authorization", Extra: map[string]string{"jwks": keyURL}}
	probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, base.URL, forgeHeaders, base.Body, forgeResp, forgeBody, "jwt-hs256-confusion")
	_, _ = saveProbeExchange(db, proj.ID, base, base.URL, anonHeaders, base.Body, anonResp, anonBody, "jwt-key-anon-baseline")
	_, _ = saveProbeExchange(db, proj.ID, base, base.URL, garbageHeaders, base.Body, garbageResp, garbageBody, "jwt-key-garbage-oracle")
	probe.Status = forgeResp.StatusCode
	probe.Length = len(forgeBody)

	if forgeResp.StatusCode == authResp.StatusCode && garbageResp.StatusCode != forgeResp.StatusCode {
		probe.Result = fmt.Sprintf(
			"endpoint returns %d with the real JWT and %d with a forged HS256 token signed using the RSA public key exposed at %s (unauthenticated %d, invalid tokens %d) — the verifier accepts HMAC with the public key as the secret, enabling arbitrary identity forgery",
			authResp.StatusCode, forgeResp.StatusCode, keyURL, anonResp.StatusCode, garbageResp.StatusCode)
		probe.Confidence = "high"
		probe.Severity = "critical"
	}
	return probe
}

// bearerToken extracts a JWT from the Authorization: Bearer header.
func bearerToken(headers []models.Header) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Authorization") && strings.HasPrefix(h.Value, "Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(h.Value, "Bearer "))
		}
	}
	return ""
}

// jwtRoleClaim decodes the role claim of a JWT payload (no signature check —
// used only to classify the token the scanner was given).
func jwtRoleClaim(bearer string) string {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]interface{}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	if r, ok := claims["role"].(string); ok {
		return strings.ToLower(r)
	}
	return ""
}

// fetchJWKSPublicKey looks for the origin's JWKS document and returns the
// RSA public key bytes (DER) to use as an HMAC secret, plus the URL it came
// from. Returns an error when no usable key is published.
func fetchJWKSPublicKey(ctx context.Context, client *httpclient.Client, rawURL string) ([]byte, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	candidates := []string{
		u.Scheme + "://" + u.Host + "/.well-known/jwks.json",
		u.Scheme + "://" + u.Host + "/.well-known/openid-configuration",
		u.Scheme + "://" + u.Host + "/jwks.json",
		u.Scheme + "://" + u.Host + "/oauth/jwks.json",
		u.Scheme + "://" + u.Host + "/auth/jwks.json",
	}
	for _, cu := range candidates {
		resp, body, err := client.Do(ctx, http.MethodGet, cu, map[string]string{"User-Agent": "AgentBurp-Scanner/0.1"}, nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		var doc map[string]interface{}
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		// openid-configuration redirects to the real JWKS URI.
		if jwksURI, ok := doc["jwks_uri"].(string); ok && jwksURI != "" {
			ru, err := url.Parse(jwksURI)
			if err != nil {
				continue
			}
			if ru.Host == "" {
				ru.Scheme, ru.Host = u.Scheme, u.Host
			}
			if ru.Host != u.Host {
				continue // only trust same-origin key material
			}
			resp2, body2, err := client.Do(ctx, http.MethodGet, ru.String(), map[string]string{"User-Agent": "AgentBurp-Scanner/0.1"}, nil)
			if err != nil || resp2.StatusCode != 200 {
				continue
			}
			if json.Unmarshal(body2, &doc) != nil {
				continue
			}
		}
		keys, ok := doc["keys"].([]interface{})
		if !ok || len(keys) == 0 {
			continue
		}
		for _, raw := range keys {
			key, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if certs, ok := key["x5c"].([]interface{}); ok && len(certs) > 0 {
				if der, err := base64.StdEncoding.DecodeString(fmt.Sprint(certs[0])); err == nil && len(der) > 0 {
					return der, cu, nil
				}
			}
			nStr, _ := key["n"].(string)
			eStr, _ := key["e"].(string)
			if nStr == "" || eStr == "" {
				continue
			}
			nBytes, err1 := base64.RawURLEncoding.DecodeString(nStr)
			eBytes, err2 := base64.RawURLEncoding.DecodeString(eStr)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				continue
			}
			return der, cu, nil
		}
	}
	return nil, "", fmt.Errorf("no JWKS key published")
}

// probeAdminAuthz checks admin-sensitive endpoints for broken function-level
// authorization: they must not answer with sensitive data to a user-level
// token (or to no credentials at all).
func probeAdminAuthz(ctx context.Context, client *httpclient.Client, engine *scope.Engine, audit *scope.AuditLogger,
	db *core.DB, proj *core.Project, base *endpointBase, rate int) *Probe {

	if !adminSensitivePathRx.MatchString(base.URL) && !adminSensitivePathRx.MatchString(base.PathTemplate) {
		return nil
	}
	if !engine.IsInScope(base.URL) {
		audit.LogScopeViolation(base.URL, "out of scope")
		return nil
	}

	// A token whose role claim is already privileged may legitimately read
	// admin surfaces — nothing to signal.
	role := ""
	if bearer := bearerToken(base.Headers); bearer != "" {
		role = jwtRoleClaim(bearer)
	}
	if role == "admin" || role == "root" || role == "superuser" || role == "owner" || role == "administrator" {
		return nil
	}

	authHeaders := base.headerMap()
	authResp, authBody, err := client.Do(ctx, base.Method, base.URL, authHeaders, base.Body)
	if err != nil {
		return nil
	}

	anonHeaders := map[string]string{}
	for k, v := range authHeaders {
		lower := strings.ToLower(k)
		if lower == "cookie" || lower == "authorization" || lower == "x-api-key" {
			continue
		}
		anonHeaders[k] = v
	}
	anonResp, anonBody, err := client.Do(ctx, base.Method, base.URL, anonHeaders, base.Body)
	if err != nil {
		return nil
	}

	probe := &Probe{Name: "admin-authz", Position: "headers", Extra: map[string]string{}}
	probe.RequestID, probe.ResponseID = saveProbeExchange(db, proj.ID, base, base.URL, authHeaders, base.Body, authResp, authBody, "admin-authz")
	_, _ = saveProbeExchange(db, proj.ID, base, base.URL, anonHeaders, base.Body, anonResp, anonBody, "admin-authz-anon-baseline")
	probe.Status = authResp.StatusCode
	probe.Length = len(authBody)

	sensitive := adminSensitiveBody(authBody) || adminSensitiveBody(anonBody)
	if !sensitive {
		return probe
	}

	switch {
	case role != "":
		probe.Result = fmt.Sprintf(
			"admin-sensitive endpoint %s returns %d with a user-level token (role=%s) and sensitive data in the response — broken function-level authorization",
			base.URL, authResp.StatusCode, role)
		probe.Confidence = "high"
		probe.Severity = "critical"
	case authResp.StatusCode == 200 && anonResp.StatusCode == 200:
		probe.Result = fmt.Sprintf(
			"admin-sensitive endpoint %s returns 200 with and without credentials and exposes sensitive data — broken function-level authorization",
			base.URL)
		probe.Confidence = "high"
		probe.Severity = "high"
	case authResp.StatusCode == 200:
		probe.Result = fmt.Sprintf(
			"admin-sensitive endpoint %s returns 200 with sensitive data while unauthenticated requests receive %d — verify that role checks are enforced server-side (possible broken function-level authorization)",
			base.URL, anonResp.StatusCode)
		probe.Confidence = "low"
		probe.Severity = "medium"
	}
	return probe
}

// adminSensitiveBody reports whether a response body looks like admin data:
// user listings, credentials, credit, orders, or role material.
func adminSensitiveBody(body []byte) bool {
	return adminDataRx.Match(body)
}

var adminDataRx = regexp.MustCompile(`(?i)("users"|"email"|"credit"|"orders"|"password"|is_admin|"role"|"balance"|"available_credit")`)

func base64URLEncode(b []byte) string {
	return strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=")
}

// looksLikeAuthChallenge reports whether a response body is an authentication
// challenge: a login form with a password input, or an access-denied page.
func looksLikeAuthChallenge(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	if passwordInputRe.Match(body) {
		return true
	}
	if strings.Contains(lower, "access denied") || strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "authentication required") || strings.Contains(lower, "forbidden") {
		return true
	}
	return false
}

var passwordInputRe = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?password["']?`)

// preAuthPathRx matches endpoints that are public by design (login, signup,
// registration, OTP verification, password recovery, token refresh). These
// answer identically with and without credentials, so "same response with
// and without credentials" must not be signaled on them.
var preAuthPathRx = regexp.MustCompile(`(?i)(/login|/signup|/sign-up|/register|/forgot|/forget|reset-password|reset_password|check-otp|check_otp|send-otp|verify-otp|verify-email|verify-phone|refresh-token|refresh_token|token-refresh|/refresh|/logout|/otp|/token\b)`)

// adminSensitivePathRx matches admin/management surfaces whose protection is
// role-based (broken function-level authorization is a common defect there).
var adminSensitivePathRx = regexp.MustCompile(`(?i)(/admin|/management|/internal|/superuser|users/all|orders/all|/moderator)`)

// applyPosition injects payload into the URL or body at a position.
func applyPosition(base *endpointBase, position, payload string) (string, []byte, bool) {
	kind, name, _ := strings.Cut(position, ".")
	if name == "" {
		return "", nil, false
	}
	if kind == "query" {
		u, err := url.Parse(base.URL)
		if err != nil {
			return "", nil, false
		}
		q := u.Query()
		q.Set(name, payload)
		u.RawQuery = q.Encode()
		return u.String(), base.Body, true
	}
	if kind == "body" {
		body := base.Body
		if len(body) == 0 {
			return "", nil, false
		}
		trimmed := strings.TrimSpace(string(body))
		if strings.HasPrefix(trimmed, "{") {
			var obj map[string]interface{}
			if json.Unmarshal(body, &obj) != nil {
				return "", nil, false
			}
			obj[name] = payload
			updated, _ := json.Marshal(obj)
			return base.URL, updated, true
		}
		if strings.Contains(trimmed, "=") {
			vals, err := url.ParseQuery(trimmed)
			if err != nil {
				return "", nil, false
			}
			vals.Set(name, payload)
			return base.URL, []byte(vals.Encode()), true
		}
	}
	return "", nil, false
}

// headerMap converts stored headers into a map (keeps the last value).
func (b *endpointBase) headerMap() map[string]string {
	out := map[string]string{}
	for _, h := range b.Headers {
		out[h.Name] = h.Value
	}
	if _, ok := out["User-Agent"]; !ok {
		out["User-Agent"] = "AgentBurp-Scanner/0.1"
	}
	return out
}

// saveProbeExchange persists a probe request+response (source=scanner).
func saveProbeExchange(db *core.DB, projectID string, base *endpointBase, rawURL string,
	headers map[string]string, body []byte, resp *http.Response, respBody []byte, probeName string) (string, string) {

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

	reqHeaders := make([]models.Header, 0, len(headers))
	for k, v := range headers {
		reqHeaders = append(reqHeaders, models.Header{Name: k, Value: v})
	}
	reqHeadersJSON, _ := json.Marshal(reqHeaders)

	db.Conn().Exec(`
		INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
			query_string, headers_json, body_blob, body_hash, session_id, endpoint_id, note, created_at)
		VALUES (?, ?, 'scanner', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reqID, projectID, base.Method, rawURL, host, port, scheme, path,
		queryOf(rawURL), string(reqHeadersJSON), body, hashBytes(body),
		base.SessionID, base.EndpointID, "active-scan:"+probeName, now,
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
	db.Conn().Exec(`
		INSERT INTO responses (id, request_id, status_code, reason, headers_json, body_blob,
			body_hash, content_type, length_bytes, time_ms, created_at)
		VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?)`,
		respID, reqID, resp.StatusCode, string(respHeadersJSON), respBody,
		hashBytes(respBody), ct, len(respBody), 0, now,
	)
	return reqID, respID
}

func queryOf(rawURL string) string {
	if i := strings.IndexByte(rawURL, '?'); i != -1 {
		return rawURL[i+1:]
	}
	return ""
}

func hashBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// saveActiveFinding persists a probe result as a finding.
func saveActiveFinding(findings *FindingsStore, base *endpointBase, probe *Probe) {
	if probe.Result == "" {
		return
	}
	sig := &models.Signal{
		ID:         newSignalID(),
		Type:       "active",
		CheckID:    probe.Name,
		Title:      probe.Title(),
		Severity:   probe.Severity,
		Confidence: probe.Confidence,
		EndpointID: base.EndpointID,
		RequestID:  probe.RequestID,
		ResponseID: probe.ResponseID,
		Evidence: map[string]interface{}{
			"position": probe.Position,
			"payload":  probe.Payload,
			"status":   probe.Status,
			"length":   probe.Length,
			"signal":   probe.Result,
			"endpoint": base.URL,
		},
		Explanation: probe.Result,
		Remediation: probe.Remediation(),
	}
	findings.Save(sig)
}

// Title renders the finding title for a probe.
func (p *Probe) Title() string {
	switch p.Name {
	case "reflected-xss":
		return "Reflected input detected (XSS surface)"
	case "sqli-error":
		return "SQL injection error signal"
	case "path-traversal":
		return "Path traversal / local file inclusion"
	case "idor-signal":
		return "Sequential object IDs enumerable (IDOR surface)"
	case "auth-bypass":
		return "Authorization bypass — endpoint accessible without credentials"
	case "stored-xss":
		return "Stored XSS — input persisted and reflected in later responses"
	case "jwt-alg-none":
		return "JWT algorithm confusion — alg=none accepted (authentication bypass)"
	case "jwt-hs256-confusion":
		return "JWT algorithm confusion — HS256 with public key accepted (identity forgery)"
	case "admin-authz":
		return "Broken function-level authorization — admin endpoint reachable with user-level access"
	default:
		return p.Name
	}
}

// Remediation renders remediation guidance for a probe.
func (p *Probe) Remediation() string {
	switch p.Name {
	case "reflected-xss":
		return "Encode all user input in the output context (HTML, attribute, JS). Consider a strict Content-Security-Policy."
	case "sqli-error":
		return "Use parameterized queries exclusively; never concatenate input into SQL. Disable verbose database errors."
	case "path-traversal":
		return "Validate and canonicalize file paths server-side; reject traversal sequences (../, ..\\), enforce allow-list, and never concatenate user input into file system paths."
	case "idor-signal":
		return "Authorize every object access server-side (the user must own or be permitted to access the resource). Consider non-sequential identifiers (UUIDs)."
	case "auth-bypass":
		return "Enforce authentication and authorization on every endpoint and method; do not rely on client-side gating."
	case "stored-xss":
		return "Validate and encode all user input on output in every context where it is rendered. Treat every stored field as untrusted, including data written by other users."
	case "jwt-alg-none":
		return "Pin the JWT signing algorithm (do not honor alg=none), verify signatures against the public key, and reject tokens whose header does not match the expected algorithm."
	case "jwt-hs256-confusion":
		return "Verify JWT signatures only with the asymmetric algorithm the key belongs to (RS256/ES256/PS256). Reject HS256 tokens for RSA keys, never use the public key (JWKS n/e or x5c) as an HMAC secret, and pin allowed algorithms on the verifier."
	case "admin-authz":
		return "Enforce role-based access control server-side on every endpoint and method. Derive the caller's role from the verified token, never from the path, client-side gating, or hidden UI."
	default:
		return ""
	}
}
