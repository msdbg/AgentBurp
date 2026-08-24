package scanner

import (
	"net/http"
	"strings"
	"testing"

	"github.com/msdbg/AgentBurp/internal/core"
)

func mkExchange() *Exchange {
	return &Exchange{
		RequestID:   "req_a",
		ResponseID:  "resp_a",
		EndpointID:  "ep_a",
		Method:      "GET",
		URL:         "http://example.com/",
		Host:        "example.com",
		Path:        "/",
		Scheme:      "http",
		ReqHeaders:  http.Header{},
		RespHeaders: http.Header{},
	}
}

func TestMissingSecurityHeaders(t *testing.T) {
	ex := mkExchange()
	sig := checkMissingSecurityHeaders(ex)
	if sig == nil || sig.CheckID != "missing-security-headers" {
		t.Fatalf("expected missing-headers signal, got %+v", sig)
	}
	missing := sig.Evidence["missing_headers"].([]string)
	if len(missing) < 4 {
		t.Errorf("expected >=4 missing headers, got %v", missing)
	}

	ex.RespHeaders.Set("Strict-Transport-Security", "max-age=31536000")
	ex.RespHeaders.Set("Content-Security-Policy", "default-src 'self'")
	ex.RespHeaders.Set("X-Frame-Options", "DENY")
	ex.RespHeaders.Set("X-Content-Type-Options", "nosniff")
	ex.RespHeaders.Set("Referrer-Policy", "no-referrer")
	if sig := checkMissingSecurityHeaders(ex); sig != nil {
		t.Errorf("no signal expected when all headers present, got %+v", sig)
	}
}

func TestCookieFlags(t *testing.T) {
	ex := mkExchange()
	ex.RespHeaders.Add("Set-Cookie", "session=abc123")
	sig := checkCookieFlags(ex)
	if sig == nil || sig.CheckID != "cookie-flags" {
		t.Fatalf("expected cookie-flags signal, got %+v", sig)
	}

	ex.RespHeaders = http.Header{}
	ex.RespHeaders.Add("Set-Cookie", "session=abc123; Secure; HttpOnly; SameSite=Lax")
	if sig := checkCookieFlags(ex); sig != nil {
		t.Errorf("no signal expected for hardened cookie, got %+v", sig)
	}

	// Secure missing on HTTPS with session cookie → medium.
	ex = mkExchange()
	ex.Scheme = "https"
	ex.RespHeaders.Add("Set-Cookie", "session=abc123; HttpOnly; SameSite=Lax")
	sig = checkCookieFlags(ex)
	if sig == nil || sig.Severity != "medium" {
		t.Errorf("expected medium severity for non-Secure session cookie on HTTPS, got %+v", sig)
	}
}

func TestCORS(t *testing.T) {
	// Wildcard + credentials → high.
	ex := mkExchange()
	ex.RespHeaders.Set("Access-Control-Allow-Origin", "*")
	ex.RespHeaders.Set("Access-Control-Allow-Credentials", "true")
	sig := checkCORS(ex)
	if sig == nil || sig.Severity != "high" {
		t.Fatalf("expected high CORS signal, got %+v", sig)
	}

	// Reflected origin → medium.
	ex = mkExchange()
	ex.ReqHeaders.Set("Origin", "https://evil.example")
	ex.RespHeaders.Set("Access-Control-Allow-Origin", "https://evil.example")
	sig = checkCORS(ex)
	if sig == nil || sig.Severity != "medium" {
		t.Fatalf("expected medium reflected-origin signal, got %+v", sig)
	}

	// Explicit trusted origin → none.
	ex = mkExchange()
	ex.ReqHeaders.Set("Origin", "https://evil.example")
	ex.RespHeaders.Set("Access-Control-Allow-Origin", "https://trusted.example")
	if sig := checkCORS(ex); sig != nil {
		t.Errorf("no signal expected for allow-listed origin, got %+v", sig)
	}
}

func TestInfoDisclosure(t *testing.T) {
	ex := mkExchange()
	ex.RespHeaders.Set("Server", "nginx/1.24.0")
	ex.RespHeaders.Set("X-Powered-By", "PHP/8.1")
	sig := checkInfoDisclosure(ex)
	if sig == nil || sig.CheckID != "info-disclosure" {
		t.Fatalf("expected info-disclosure signal, got %+v", sig)
	}

	ex = mkExchange()
	ex.RespBody = []byte(`<html><pre>Traceback (most recent call last):
  File "/app/main.py", line 42, in index
    return conn.execute(sql)
sqlite3.OperationalError: no such table: users</pre></html>`)
	sig = checkInfoDisclosure(ex)
	if sig == nil || sig.Severity != "medium" {
		t.Fatalf("expected medium stack-trace signal, got %+v", sig)
	}

	ex = mkExchange()
	ex.RespBody = []byte(`{"email":"admin@example.com","server_ip":"10.0.3.21"}`)
	sig = checkInfoDisclosure(ex)
	if sig == nil {
		t.Fatal("expected info-disclosure signal for body leaks")
	}
	leaks, _ := sig.Evidence["leaks"].([]string)
	if len(leaks) < 2 {
		t.Fatalf("expected email + IP leaks, got %v", leaks)
	}

	// Clean response → none.
	ex = mkExchange()
	ex.RespHeaders.Set("Server", "AgentBurp-Test")
	if sig := checkInfoDisclosure(ex); sig != nil {
		t.Errorf("no signal expected for clean response, got %+v", sig)
	}
}

func TestSensitiveURLParams(t *testing.T) {
	ex := mkExchange()
	ex.URL = "http://example.com/login?password=hunter2&token=abc"
	ex.Query = "password=hunter2&token=abc"
	sig := checkSensitiveURLParams(ex)
	if sig == nil || sig.Severity != "high" {
		t.Fatalf("expected high sensitive-URL signal, got %+v", sig)
	}

	ex.Query = "q=test&page=2"
	if sig := checkSensitiveURLParams(ex); sig != nil {
		t.Errorf("no signal expected for benign query, got %+v", sig)
	}
}

func TestMixedContent(t *testing.T) {
	ex := mkExchange()
	ex.Scheme = "https"
	ex.RespBody = []byte(`<script src="http://cdn.example.com/lib.js"></script><img src="http://cdn.example.com/i.png">`)
	sig := checkMixedContent(ex)
	if sig == nil {
		t.Fatal("expected mixed-content signal")
	}

	ex.Scheme = "http"
	if sig := checkMixedContent(ex); sig != nil {
		t.Errorf("no signal expected on http page, got %+v", sig)
	}
}

func TestOpenRedirect(t *testing.T) {
	ex := mkExchange()
	ex.Status = 302
	ex.Query = "next=/admin"
	ex.RespHeaders.Set("Location", "/admin")
	sig := checkOpenRedirect(ex)
	if sig == nil || sig.CheckID != "open-redirect" {
		t.Fatalf("expected open-redirect signal, got %+v", sig)
	}

	// External redirect → high.
	ex = mkExchange()
	ex.Status = 302
	ex.Query = "url=https%3A%2F%2Fevil.com%2Fphish"
	ex.RespHeaders.Set("Location", "https://evil.com/phish")
	sig = checkOpenRedirect(ex)
	if sig == nil || sig.Severity != "high" {
		t.Fatalf("expected high external open-redirect, got %+v", sig)
	}

	// Redirect not reflecting input → none.
	ex = mkExchange()
	ex.Status = 301
	ex.Query = "next=/admin"
	ex.RespHeaders.Set("Location", "/")
	if sig := checkOpenRedirect(ex); sig != nil {
		t.Errorf("no signal expected, got %+v", sig)
	}
}

func TestCSRF(t *testing.T) {
	ex := mkExchange()
	ex.Method = "POST"
	ex.Path = "/api/upload"
	ex.Status = 200
	sig := checkCSRF(ex)
	if sig == nil || sig.CheckID != "csrf-token-absent" {
		t.Fatalf("expected csrf signal, got %+v", sig)
	}

	// With a CSRF token in the body → none.
	ex = mkExchange()
	ex.Method = "POST"
	ex.Path = "/api/upload"
	ex.Status = 200
	ex.ReqBody = []byte("csrf_token=xyz&name=a")
	if sig := checkCSRF(ex); sig != nil {
		t.Errorf("no signal expected with token in body, got %+v", sig)
	}

	// GET → none.
	ex = mkExchange()
	ex.Method = "GET"
	if sig := checkCSRF(ex); sig != nil {
		t.Errorf("no signal expected for GET, got %+v", sig)
	}

	// Rejected action (401) → none.
	ex = mkExchange()
	ex.Method = "POST"
	ex.Status = 401
	if sig := checkCSRF(ex); sig != nil {
		t.Errorf("no signal expected for rejected request, got %+v", sig)
	}
}

func TestCacheControl(t *testing.T) {
	ex := mkExchange()
	ex.Path = "/api/profile"
	sig := checkCacheControl(ex)
	if sig == nil || sig.CheckID != "cache-control-missing" {
		t.Fatalf("expected cache-control signal, got %+v", sig)
	}

	ex.RespHeaders.Set("Cache-Control", "private, no-store")
	if sig := checkCacheControl(ex); sig != nil {
		t.Errorf("no signal expected with no-store, got %+v", sig)
	}

	ex = mkExchange()
	ex.Path = "/api/users"
	if sig := checkCacheControl(ex); sig != nil {
		t.Errorf("no signal expected for non-sensitive path, got %+v", sig)
	}
}

func TestHSTS(t *testing.T) {
	ex := mkExchange()
	ex.Scheme = "https"
	sig := checkHSTS(ex)
	if sig == nil || sig.CheckID != "hsts-missing" {
		t.Fatalf("expected hsts signal, got %+v", sig)
	}

	ex.RespHeaders.Set("Strict-Transport-Security", "max-age=31536000")
	if sig := checkHSTS(ex); sig != nil {
		t.Errorf("no signal expected with HSTS, got %+v", sig)
	}

	ex = mkExchange()
	ex.Scheme = "http"
	if sig := checkHSTS(ex); sig != nil {
		t.Errorf("no signal expected over http, got %+v", sig)
	}
}

func TestAllChecksRun(t *testing.T) {
	// Every check must be registered exactly once.
	if len(passiveChecks) != 13 {
		t.Errorf("expected 13 passive checks, got %d", len(passiveChecks))
	}
}

func TestSSRFParam(t *testing.T) {
	ex := mkExchange()
	ex.Query = "callback=http://evil.example/&q=apple"
	sig := checkSSRFParam(ex)
	if sig == nil || sig.CheckID != "ssrf-param" {
		t.Fatalf("expected ssrf-param signal, got %+v", sig)
	}
	params := sig.Evidence["params"].([]string)
	if len(params) != 1 || params[0] != "callback" {
		t.Errorf("expected only callback param, got %v", params)
	}

	ex = mkExchange()
	ex.Query = "q=apple"
	if sig := checkSSRFParam(ex); sig != nil {
		t.Errorf("no signal expected without URL-typed params, got %+v", sig)
	}

	ex = mkExchange()
	ex.Method = "POST"
	ex.ReqBody = []byte(`{"imageUrl":"http://127.0.0.1/metrics","title":"x"}`)
	sig = checkSSRFParam(ex)
	if sig == nil {
		t.Fatal("expected ssrf-param signal for imageUrl body field")
	}
}

func TestSensitiveFile(t *testing.T) {
	ex := mkExchange()
	ex.Status = 200
	ex.Path = "/ftp/incident-support.kdbx"
	ex.RespHeaders.Set("Content-Type", "application/octet-stream")
	ex.RespBody = []byte("kdbx-binary-bytes")
	sig := checkSensitiveFile(ex)
	if sig == nil || sig.CheckID != "sensitive-file" {
		t.Fatalf("expected sensitive-file signal, got %+v", sig)
	}
	if sig.Severity != "high" {
		t.Errorf("credential file should be high severity, got %s", sig.Severity)
	}

	// SPA fallback (text/html) must not be flagged.
	ex = mkExchange()
	ex.Status = 200
	ex.Path = "/ftp/coupons_2013.md.bak"
	ex.RespHeaders.Set("Content-Type", "text/html; charset=UTF-8")
	ex.RespBody = []byte("<html>SPA fallback</html>")
	if sig := checkSensitiveFile(ex); sig != nil {
		t.Errorf("HTML fallback must not be flagged, got %+v", sig)
	}

	// Non-200 must not be flagged.
	ex = mkExchange()
	ex.Status = 403
	ex.Path = "/ftp/package.json.bak"
	ex.RespHeaders.Set("Content-Type", "application/octet-stream")
	ex.RespBody = []byte("denied")
	if sig := checkSensitiveFile(ex); sig != nil {
		t.Errorf("403 must not be flagged, got %+v", sig)
	}

	// .md is not in the sensitive extension list.
	ex = mkExchange()
	ex.Status = 200
	ex.Path = "/ftp/acquisitions.md"
	ex.RespHeaders.Set("Content-Type", "text/markdown")
	ex.RespBody = []byte("# confidential")
	if sig := checkSensitiveFile(ex); sig != nil {
		t.Errorf(".md must not be flagged as sensitive file, got %+v", sig)
	}
}

func TestCredentialDisclosure(t *testing.T) {
	// JDBC connection string with credentials → high.
	ex := mkExchange()
	ex.RespBody = []byte(`Error: No suitable driver found for jdbc:postgresql://db.example.com:5432/userdb?user=dbadmin&password=SuperSecretDB2024!&ssl=true`)
	sig := checkCredentialDisclosure(ex)
	if sig == nil || sig.CheckID != "credential-disclosure" {
		t.Fatalf("expected credential-disclosure signal, got %+v", sig)
	}
	if sig.Severity != "high" {
		t.Errorf("connection-string leak should be high, got %s", sig.Severity)
	}
	leaks := sig.Evidence["leaks"].([]string)
	if len(leaks) != 1 || !strings.Contains(leaks[0], "jdbc:postgresql") {
		t.Errorf("expected jdbc leak evidence, got %v", leaks)
	}

	// AWS access key → high.
	ex = mkExchange()
	ex.RespBody = []byte(`{"iam": "AKIAIOSFODNN7EXAMPLE"}`)
	sig = checkCredentialDisclosure(ex)
	if sig == nil || sig.Severity != "high" {
		t.Fatalf("expected high AWS-key signal, got %+v", sig)
	}

	// Private key block → high.
	ex = mkExchange()
	ex.RespBody = []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")
	sig = checkCredentialDisclosure(ex)
	if sig == nil || sig.Severity != "high" {
		t.Fatalf("expected high private-key signal, got %+v", sig)
	}

	// Generic password=value in body → medium.
	ex = mkExchange()
	ex.RespBody = []byte(`<pre>CONFIG: password=hunter2 db=prod</pre>`)
	sig = checkCredentialDisclosure(ex)
	if sig == nil || sig.Severity != "medium" {
		t.Fatalf("expected medium generic-credential signal, got %+v", sig)
	}

	// Placeholder values must not be flagged.
	for _, v := range []string{"password=PASSWORD", "password=********", "api_key=XXXX"} {
		ex = mkExchange()
		ex.RespBody = []byte("config: " + v)
		if sig := checkCredentialDisclosure(ex); sig != nil {
			t.Errorf("placeholder %q must not be flagged, got %+v", v, sig)
		}
	}

	// Code samples (e.g. `password = secret();`) must not be flagged.
	ex = mkExchange()
	ex.RespBody = []byte(`def login(): password = secret(); return ok`)
	if sig := checkCredentialDisclosure(ex); sig != nil {
		t.Errorf("code sample must not be flagged, got %+v", sig)
	}

	// Clean body → none.
	ex = mkExchange()
	ex.RespBody = []byte(`<html><p>Welcome to the app</p></html>`)
	if sig := checkCredentialDisclosure(ex); sig != nil {
		t.Errorf("no signal expected for clean body, got %+v", sig)
	}
}

func TestFindingsSaveDedupByEndpoint(t *testing.T) {
	db, proj := setupTestDB(t)
	defer db.Close()
	store := NewFindingsStore(db, proj.ID)
	now := core.TimestampNow()

	seedExchange := func(id, epID, path string) {
		reqID := "req_" + id
		respID := "resp_" + id
		db.Conn().Exec(`INSERT INTO endpoints (id, project_id, host, method, path_template, canonical_path, first_seen, last_seen)
			VALUES (?, ?, 'example.com', 'GET', ?, ?, ?, ?)`, epID, proj.ID, path, path, now, now)
		db.Conn().Exec(`INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path, query_string, headers_json, body_blob, body_hash, session_id, endpoint_id, note, created_at)
			VALUES (?, ?, 'proxy', 'GET', ?, 'example.com', 80, 'http', ?, '', '[]', '', '', '', ?, '', ?)`,
			reqID, proj.ID, "http://example.com"+path, path, epID, now)
		db.Conn().Exec(`INSERT INTO responses (id, request_id, status_code, headers_json, body_blob, body_hash, content_type, length_bytes, time_ms, created_at)
			VALUES (?, ?, 200, '[]', '', '', 'text/html', 0, 0, ?)`, respID, reqID, now)
	}
	seedExchange("a", "ep_x", "/")
	seedExchange("b", "ep_x", "/")
	seedExchange("c", "ep_x", "/")
	seedExchange("d", "ep_y", "/other")

	first := signalFrom(&Exchange{RequestID: "req_a", ResponseID: "resp_a", EndpointID: "ep_x", URL: "http://example.com/"}, "missing-security-headers", "t", "low", "high")
	created, err := store.Save(first)
	if err != nil || !created {
		t.Fatalf("first save should create, got created=%v err=%v", created, err)
	}

	// Same endpoint + check from a different request (fuzzer run, re-crawl)
	// must dedup into the existing finding.
	dup := signalFrom(&Exchange{RequestID: "req_b", ResponseID: "resp_b", EndpointID: "ep_x", URL: "http://example.com/"}, "missing-security-headers", "t", "low", "high")
	created, err = store.Save(dup)
	if err != nil || created {
		t.Fatalf("duplicate save should dedup, got created=%v err=%v", created, err)
	}

	// A different check on the same endpoint is a distinct finding.
	other := signalFrom(&Exchange{RequestID: "req_c", ResponseID: "resp_c", EndpointID: "ep_x", URL: "http://example.com/"}, "cookie-flags", "t", "low", "high")
	created, err = store.Save(other)
	if err != nil || !created {
		t.Fatalf("different check should create, got created=%v err=%v", created, err)
	}

	// Same check on a different endpoint is a distinct finding.
	otherEP := signalFrom(&Exchange{RequestID: "req_d", ResponseID: "resp_d", EndpointID: "ep_y", URL: "http://example.com/other"}, "missing-security-headers", "t", "low", "high")
	created, err = store.Save(otherEP)
	if err != nil || !created {
		t.Fatalf("different endpoint should create, got created=%v err=%v", created, err)
	}

	// After marking the original as false positive, a retest creates anew.
	store.MarkFalsePositive(first.ID)
	again := signalFrom(&Exchange{RequestID: "req_d", ResponseID: "resp_d", EndpointID: "ep_x", URL: "http://example.com/"}, "missing-security-headers", "t", "low", "high")
	created, err = store.Save(again)
	if err != nil || !created {
		t.Fatalf("retest after FP should create, got created=%v err=%v", created, err)
	}
}

func TestInfoDisclosureIgnoresDescriptionText(t *testing.T) {
	// Mere mentions of the words "stack trace" in documentation/descriptions
	// must not be flagged as an actual stack trace leak.
	ex := mkExchange()
	ex.RespBody = []byte(`<p>Exception stack traces in monitoring tools like Sentry, Rollbar, or CloudWatch</p>`)
	if sig := checkInfoDisclosure(ex); sig != nil {
		t.Errorf("description text must not be flagged, got %+v", sig)
	}

	// Actual SQL error output is still detected.
	ex = mkExchange()
	ex.RespBody = []byte(`ERROR: SQLSTATE[HY000] [1045] Access denied for user 'app'@'localhost'`)
	sig := checkInfoDisclosure(ex)
	if sig == nil || sig.Severity != "medium" {
		t.Fatalf("expected medium SQL-error signal, got %+v", sig)
	}
}

func TestInfoDisclosureStackTraceStatusGate(t *testing.T) {
	// Framework class names in a 200 response (dependency listing) must not
	// be flagged.
	ex := mkExchange()
	ex.Status = 200
	ex.RespBody = []byte(`org.springframework:spring-web:6.1.5 (used by WebGoat, listed in the dependency tree)`)
	if sig := checkInfoDisclosure(ex); sig != nil {
		t.Errorf("framework class names in 200 must not be flagged, got %+v", sig)
	}

	// The same text in a 4xx/5xx error response (Spring Boot default error
	// JSON with "trace" field and "at org.springframework..." frames) is a
	// genuine stack trace leak.
	ex = mkExchange()
	ex.Status = 400
	ex.RespBody = []byte(`{"status":400,"error":"Bad Request","trace":"org.springframework.web.bind.MissingServletRequestParameterException: Required request parameter 'query' is not present` + "\n" + `	at org.springframework.web.method.annotation.RequestParamMethodArgumentResolver.handleMissingValue(RequestParamMethodArgumentResolver.java:206)"}`)
	sig := checkInfoDisclosure(ex)
	if sig == nil {
		t.Fatalf("expected info-disclosure signal for Spring trace in 4xx, got nil")
	}
	if sig.Severity != "medium" || sig.Confidence != "high" {
		t.Errorf("expected medium/high, got %s/%s", sig.Severity, sig.Confidence)
	}

	// "at java.xxx" frame in a 500 also triggers via the error regex.
	ex = mkExchange()
	ex.Status = 500
	ex.RespBody = []byte(`Caused by: java.lang.NullPointerException: Cannot invoke "String.contains(java.lang.CharSequence)"`)
	sig = checkInfoDisclosure(ex)
	if sig == nil {
		t.Fatalf("expected info-disclosure signal for Caused by line in 5xx, got nil")
	}
}
