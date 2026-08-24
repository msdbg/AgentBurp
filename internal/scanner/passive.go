package scanner

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

// Exchange is one stored request+response pair, loaded for scanning.
type Exchange struct {
	RequestID   string
	ResponseID  string
	EndpointID  string
	Method      string
	URL         string
	Host        string
	Path        string
	Query       string
	Scheme      string
	ReqHeaders  http.Header
	ReqBody     []byte
	Status      int
	RespHeaders http.Header
	RespBody    []byte
}

// signalFrom builds a finding skeleton shared by all checks.
func signalFrom(ex *Exchange, checkID, title, sev, conf string) *models.Signal {
	return &models.Signal{
		ID:         newSignalID(),
		Type:       "passive",
		CheckID:    checkID,
		Title:      title,
		Severity:   sev,
		Confidence: conf,
		EndpointID: ex.EndpointID,
		RequestID:  ex.RequestID,
		ResponseID: ex.ResponseID,
		Evidence:   map[string]interface{}{},
	}
}

// loadExchanges reads stored traffic for scanning. When reqID is empty,
// all requests with stored responses are returned (newest first).
func loadExchanges(conn *sql.DB, projectID, reqID string) ([]*Exchange, error) {
	q := `
		SELECT r.id, COALESCE(r.endpoint_id,''), r.method, r.url, r.host, r.path,
		       r.query_string, r.scheme, r.headers_json, r.body_blob,
		       COALESCE(resp.id,''), COALESCE(resp.status_code, 0), COALESCE(resp.headers_json,'[]'), resp.body_blob
		FROM requests r
		LEFT JOIN responses resp ON resp.request_id = r.id
		WHERE r.project_id = ?`
	args := []interface{}{projectID}
	if reqID != "" {
		q += " AND r.id = ?"
		args = append(args, reqID)
	}
	q += " ORDER BY r.created_at DESC"

	rows, err := conn.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Exchange
	for rows.Next() {
		ex := &Exchange{}
		var reqHeadersJSON, respHeadersJSON string
		var reqBody, respBody []byte
		var respID string
		if err := rows.Scan(&ex.RequestID, &ex.EndpointID, &ex.Method, &ex.URL, &ex.Host,
			&ex.Path, &ex.Query, &ex.Scheme, &reqHeadersJSON, &reqBody,
			&respID, &ex.Status, &respHeadersJSON, &respBody); err != nil {
			return nil, err
		}
		if respID == "" || ex.Status == 0 {
			continue // no stored response to analyze
		}
		ex.ResponseID = respID
		ex.ReqHeaders = parseHeaderJSON(reqHeadersJSON)
		ex.RespHeaders = parseHeaderJSON(respHeadersJSON)
		ex.ReqBody = reqBody
		ex.RespBody = respBody
		out = append(out, ex)
	}
	return out, rows.Err()
}

func parseHeaderJSON(raw string) http.Header {
	h := http.Header{}
	var pairs []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return h
	}
	for _, p := range pairs {
		h.Add(p.Name, p.Value)
	}
	return h
}

func ctOf(ex *Exchange) string {
	return strings.ToLower(strings.SplitN(ex.RespHeaders.Get("Content-Type"), ";", 2)[0])
}

func newSignalID() string {
	return core.NewID("sig")
}

// ─── Checks ──────────────────────────────────────────────────────────────────

var sensitiveURLParams = []string{"password", "passwd", "pwd", "token", "api_key", "apikey", "api-key",
	"secret", "auth", "credential", "session_id", "sessionid", "access_token", "refresh_token", "key"}

var sensitivePathRx = regexp.MustCompile(`(?i)(login|auth|token|password|profile|account|admin|session|credit|card|payment|balance|secret)`)

// stackTraceRx only matches actual stack traces or SQL/driver error output,
// not mere mentions of the words "stack trace" in documentation text.
// It deliberately excludes framework class names (org.springframework,
// jakarta, ...): dependency listings and documentation pages legitimately
// mention them.
var stackTraceRx = regexp.MustCompile(`(?i)(Traceback \(most recent call last\)|at [a-z][a-z0-9_.]+\([^)]*\.(java|py|go|cpp|cs):\d+\)|SQLSTATE|ORA-\d{4,5}|SQLiteException|psycopg2?|com\.\w+\.(exceptions|dao|service|controller)\.|System\.(Exception|ArgumentNull)|Exception in thread|No suitable driver found)`)

// stackTraceErrorRx additionally matches framework exception class names,
// "at org.springframework/..." frame lines, and Spring Boot's JSON "trace"
// field. These only appear in genuine error responses, so they are only
// applied to 4xx/5xx responses where the status gate rules out
// dependency-listing and documentation false positives.
var stackTraceErrorRx = regexp.MustCompile(`(?i)(Caused by:|at (?:org\.springframework|jakarta\.|java\.|org\.apache\.)[a-z0-9_.]+\([^)]*\)|(?:org\.springframework|jakarta\.|java\.|org\.apache\.)[a-z0-9_.]*Exception|"trace"\s*:)`)

var emailRx = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

var internalIPRx = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

var redirectParams = []string{"url", "redirect", "next", "return", "dest", "target", "goto", "u", "r", "out"}

// checkMissingSecurityHeaders flags missing baseline security headers.
func checkMissingSecurityHeaders(ex *Exchange) *models.Signal {
	expected := []struct {
		name string
		sev  string
	}{
		{"Strict-Transport-Security", "low"},
		{"Content-Security-Policy", "low"},
		{"X-Frame-Options", "low"},
		{"X-Content-Type-Options", "info"},
		{"Referrer-Policy", "info"},
	}
	var missing []string
	for _, h := range expected {
		if ex.RespHeaders.Get(h.name) == "" {
			missing = append(missing, h.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sig := signalFrom(ex, "missing-security-headers",
		"Missing security headers", "low", "high")
	sig.Evidence["missing_headers"] = missing
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "The response does not set one or more baseline security headers: " +
		strings.Join(missing, ", ") + ". These headers mitigate clickjacking, MIME sniffing, mixed content, and protocol downgrade attacks."
	sig.Remediation = "Set Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy on all responses."
	return sig
}

// checkCookieFlags flags cookies without hardening attributes.
func checkCookieFlags(ex *Exchange) *models.Signal {
	setCookies := ex.RespHeaders.Values("Set-Cookie")
	if len(setCookies) == 0 {
		return nil
	}
	type cookieIssue struct {
		Name    string   `json:"name"`
		Missing []string `json:"missing_flags"`
	}
	var issues []cookieIssue
	for _, raw := range setCookies {
		parts := strings.Split(raw, ";")
		name := strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0])
		var missing []string
		if !hasFlag(parts, "secure") {
			missing = append(missing, "Secure")
		}
		if !hasFlag(parts, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !hasFlag(parts, "samesite") {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			issues = append(issues, cookieIssue{Name: name, Missing: missing})
		}
	}
	if len(issues) == 0 {
		return nil
	}
	sev := "low"
	for _, i := range issues {
		for _, m := range i.Missing {
			if m == "Secure" && ex.Scheme == "https" {
				sev = "medium"
			}
			if m == "HttpOnly" && strings.Contains(strings.ToLower(i.Name), "session") {
				sev = "medium"
			}
		}
	}
	sig := signalFrom(ex, "cookie-flags", "Cookies missing security flags", sev, "high")
	sig.Evidence["cookies"] = issues
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "One or more Set-Cookie headers lack Secure, HttpOnly, or SameSite attributes, " +
		"leaving cookies exposed to theft over HTTP, XSS exfiltration, or CSRF."
	sig.Remediation = "Set Secure, HttpOnly, and SameSite attributes on all cookies. Session cookies must be HttpOnly; auth cookies must be Secure over HTTPS."
	return sig
}

func hasFlag(parts []string, flag string) bool {
	for _, p := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(p, "=", 2)[0]), flag) {
			return true
		}
	}
	return false
}

// checkCORS flags dangerous Access-Control-Allow-Origin configurations.
func checkCORS(ex *Exchange) *models.Signal {
	acao := ex.RespHeaders.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}
	acac := ex.RespHeaders.Get("Access-Control-Allow-Credentials")
	origin := ex.ReqHeaders.Get("Origin")

	if acao == "*" && strings.EqualFold(acac, "true") {
		sig := signalFrom(ex, "cors-misconfiguration",
			"CORS allows any origin with credentials", "high", "high")
		sig.Evidence = map[string]interface{}{"acao": acao, "allow_credentials": acac, "url": ex.URL}
		sig.Explanation = "The response reflects Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers will not enforce credential scoping for wildcard origins, and any site can read this endpoint's data with the user's cookies."
		sig.Remediation = "Never combine a wildcard origin with credentials. Reflect only trusted, allow-listed origins."
		return sig
	}
	if origin != "" && acao == origin {
		conf, sev := "medium", "medium"
		expl := "The response reflects the request Origin header back in Access-Control-Allow-Origin. Any malicious site can set an Origin header and receive cross-origin read access"
		if strings.EqualFold(acac, "true") {
			sev = "high"
			expl += ", including credentialed requests."
		} else {
			expl += "."
		}
		sig := signalFrom(ex, "cors-misconfiguration",
			"CORS reflects request origin", sev, conf)
		sig.Evidence = map[string]interface{}{"origin": origin, "acao": acao, "allow_credentials": acac, "url": ex.URL}
		sig.Explanation = expl
		sig.Remediation = "Allow-list specific origins instead of reflecting the Origin header. Validate Origin against a trusted list server-side."
		return sig
	}
	return nil
}

// checkInfoDisclosure flags server banners, debug headers, and leaked data.
func checkInfoDisclosure(ex *Exchange) *models.Signal {
	var leaks []string

	if v := ex.RespHeaders.Get("Server"); v != "" && versionRx.MatchString(v) {
		leaks = append(leaks, fmt.Sprintf("Server header reveals version: %s", v))
	}
	for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-Debug", "X-Debug-Info", "X-Generator", "X-Backend-Server", "X-Backend"} {
		if v := ex.RespHeaders.Get(h); v != "" {
			leaks = append(leaks, fmt.Sprintf("%s header: %s", h, v))
		}
	}
	body := string(ex.RespBody)
	hasTrace := stackTraceRx.MatchString(body) || (ex.Status >= 400 && stackTraceErrorRx.MatchString(body))
	if hasTrace {
		leaks = append(leaks, "response body contains stack trace or SQL error details")
	}
	if m := internalIPRx.FindString(body); m != "" {
		leaks = append(leaks, "response body contains internal IP address: "+m)
	}
	if m := emailRx.FindString(body); m != "" {
		leaks = append(leaks, "response body contains email address: "+m)
	}
	if len(leaks) == 0 {
		return nil
	}
	sev, conf := "low", "medium"
	if hasTrace {
		sev = "medium"
		conf = "high"
	}
	sig := signalFrom(ex, "info-disclosure", "Information disclosure detected", sev, conf)
	sig.Evidence["leaks"] = leaks
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "The response exposes implementation details: " + strings.Join(leaks, "; ") + ". This aids attackers in fingerprinting and exploiting the application."
	sig.Remediation = "Remove version banners and debug headers, and ensure error handlers return generic messages without stack traces, SQL errors, or internal addresses."
	return sig
}

var versionRx = regexp.MustCompile(`[0-9]+\.[0-9]+`)

// checkSensitiveURLParams flags credentials/tokens in query strings.
func checkSensitiveURLParams(ex *Exchange) *models.Signal {
	if ex.Query == "" {
		return nil
	}
	params, err := url.ParseQuery(ex.Query)
	if err != nil {
		return nil
	}
	var found []string
	for name := range params {
		lower := strings.ToLower(name)
		for _, s := range sensitiveURLParams {
			if strings.Contains(lower, s) {
				found = append(found, name)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	sev := "medium"
	for _, f := range found {
		lf := strings.ToLower(f)
		if strings.Contains(lf, "password") || strings.Contains(lf, "token") || strings.Contains(lf, "secret") {
			sev = "high"
		}
	}
	sig := signalFrom(ex, "sensitive-data-in-url",
		"Sensitive data in URL query string", sev, "high")
	sig.Evidence["params"] = found
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "The request places sensitive values (" + strings.Join(found, ", ") +
		") in the URL query string. URLs are logged by proxies, browsers, and analytics, and leak through Referer headers."
	sig.Remediation = "Move credentials and tokens to the request body or headers. Redact query strings in logs."
	return sig
}

var mixedContentRx = regexp.MustCompile(`(?i)(?:src|href|action|url)\s*=\s*["']http://[^"'\s>]+`)

// checkMixedContent flags http:// references on HTTPS pages.
func checkMixedContent(ex *Exchange) *models.Signal {
	if ex.Scheme != "https" {
		return nil
	}
	matches := mixedContentRx.FindAllString(string(ex.RespBody), 3)
	if len(matches) == 0 {
		return nil
	}
	sig := signalFrom(ex, "mixed-content", "Mixed content on HTTPS page", "medium", "high")
	sig.Evidence["url"] = ex.URL
	sig.Evidence["refs"] = matches
	sig.Explanation = "An HTTPS response references resources over plain HTTP. Browsers block active mixed content and degrade the security of the page."
	sig.Remediation = "Serve all resources over HTTPS, ideally via protocol-relative or HTTPS-only URLs."
	return sig
}

// checkOpenRedirect flags 3xx responses that reflect redirect parameters.
func checkOpenRedirect(ex *Exchange) *models.Signal {
	if ex.Status < 300 || ex.Status >= 400 {
		return nil
	}
	loc := ex.RespHeaders.Get("Location")
	if loc == "" {
		return nil
	}
	params, err := url.ParseQuery(ex.Query)
	if err != nil {
		return nil
	}
	for name, vals := range params {
		for _, s := range redirectParams {
			if strings.EqualFold(name, s) {
				for _, v := range vals {
					if v != "" && strings.Contains(loc, v) {
						sev := "medium"
						if strings.HasPrefix(loc, "http") && !strings.HasPrefix(loc, ex.Scheme+"://"+ex.Host) {
							sev = "high"
						}
						sig := signalFrom(ex, "open-redirect",
							"Open redirect — Location reflects user input", sev, "medium")
						sig.Evidence = map[string]interface{}{"param": name, "value": v, "location": loc, "url": ex.URL}
						sig.Explanation = fmt.Sprintf(
							"The %q query parameter (%q) is reflected into the Location header of this %d response. An attacker can craft a link that redirects victims to an external site (phishing).", name, v, ex.Status)
						sig.Remediation = "Only redirect to allow-listed internal paths. Validate redirect targets server-side."
						return sig
					}
				}
			}
		}
	}
	return nil
}

// checkCSRF flags state-changing requests without anti-CSRF tokens.
func checkCSRF(ex *Exchange) *models.Signal {
	switch ex.Method {
	case "POST", "PUT", "PATCH", "DELETE":
	default:
		return nil
	}
	// If the action was rejected, there is no CSRF exposure to report.
	if ex.Status == 401 || ex.Status == 403 || ex.Status == 429 {
		return nil
	}
	if hasCSRFToken(ex) {
		return nil
	}
	sig := signalFrom(ex, "csrf-token-absent",
		"State-changing request without CSRF token", "low", "medium")
	sig.Evidence["url"] = ex.URL
	sig.Evidence["method"] = ex.Method
	sig.Evidence["has_cookie"] = ex.ReqHeaders.Get("Cookie") != ""
	sig.Explanation = fmt.Sprintf(
		"The %s %s changes state but carries no CSRF token (no csrf/token field in body or headers). If the site uses cookie auth without SameSite cookies, cross-site requests can trigger actions on the user's behalf.", ex.Method, ex.Path)
	sig.Remediation = "Add a per-session CSRF token to state-changing requests, or rely on SameSite=Strict/Lax cookies plus custom-header checks."
	return sig
}

func hasCSRFToken(ex *Exchange) bool {
	for h := range ex.ReqHeaders {
		lower := strings.ToLower(h)
		if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
			return true
		}
	}
	body := string(ex.ReqBody)
	lower := strings.ToLower(body)
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "token") {
		return true
	}
	for _, c := range strings.Split(ex.ReqHeaders.Get("Cookie"), ";") {
		c = strings.TrimSpace(c)
		if strings.EqualFold(c, "csrf") || strings.HasPrefix(strings.ToLower(c), "csrf=") {
			return true
		}
	}
	return false
}

// checkCacheControl flags missing no-store on sensitive responses.
func checkCacheControl(ex *Exchange) *models.Signal {
	if !sensitivePathRx.MatchString(ex.Path) {
		return nil
	}
	cc := strings.ToLower(ex.RespHeaders.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") {
		return nil
	}
	sig := signalFrom(ex, "cache-control-missing",
		"Sensitive response missing no-store", "low", "medium")
	sig.Evidence["url"] = ex.URL
	sig.Evidence["cache_control"] = ex.RespHeaders.Get("Cache-Control")
	sig.Explanation = "A response for a sensitive resource (" + ex.Path +
		") does not set Cache-Control: no-store, so it may be cached by shared proxies or the browser."
	sig.Remediation = "Set Cache-Control: no-store on responses containing authentication data, personal data, or financial details."
	return sig
}

// checkHSTS flags HTTPS responses without Strict-Transport-Security.
func checkHSTS(ex *Exchange) *models.Signal {
	if ex.Scheme != "https" {
		return nil
	}
	if ex.RespHeaders.Get("Strict-Transport-Security") != "" {
		return nil
	}
	sig := signalFrom(ex, "hsts-missing", "HTTPS response without HSTS", "low", "high")
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "The HTTPS response does not set Strict-Transport-Security, allowing protocol-downgrade and cookie-stealing attacks on first visit."
	sig.Remediation = "Set Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses."
	return sig
}

// checkSSRFParam flags parameters that typically feed server-side URL
// fetching (SSRF surface). Detection is passive: the parameter name
// indicates the endpoint may fetch or redirect to attacker-chosen URLs.
func checkSSRFParam(ex *Exchange) *models.Signal {
	var names []string
	collect := func(n string) {
		if ssrfParamRx.MatchString(n) && !containsStr(names, n) {
			names = append(names, n)
		}
	}
	if ex.Query != "" {
		if params, err := url.ParseQuery(ex.Query); err == nil {
			for n := range params {
				collect(n)
			}
		}
	}
	if len(ex.ReqBody) > 0 {
		trimmed := strings.TrimSpace(string(ex.ReqBody))
		if strings.HasPrefix(trimmed, "{") {
			var obj map[string]interface{}
			if json.Unmarshal(ex.ReqBody, &obj) == nil {
				for k := range obj {
					collect(k)
				}
			}
		} else if strings.Contains(trimmed, "=") {
			if vals, err := url.ParseQuery(trimmed); err == nil {
				for k := range vals {
					collect(k)
				}
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	sig := signalFrom(ex, "ssrf-param",
		"URL-typed parameter (potential SSRF surface)", "info", "low")
	sig.Evidence["params"] = names
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "The request carries URL-valued parameters (" + strings.Join(names, ", ") +
		"). Endpoints that fetch or redirect to these values can be abused for server-side request forgery (internal network scan, cloud metadata at 169.254.169.254, local services). Confirm whether the value is fetched server-side and validate allow-lists."
	sig.Remediation = "Never fetch user-supplied URLs server-side. If a URL import feature is required, restrict the protocol and host to an allow-list and disable redirect following."
	return sig
}

var ssrfParamRx = regexp.MustCompile(`(?i)(^|_)(url|uri|link|target|redirect|callback|imageurl|imgurl|fetchurl|endpoint|webhook|destination)(_|$)`)

var sensitiveFileRx = regexp.MustCompile(`(?i)\.(kdbx|key|pem|pfx|p12|sql|dmp|env|tar|gz|zip|7z|jar|war|ear|bak)$`)
var credentialFileRx = regexp.MustCompile(`(?i)\.(kdbx|key|pem|pfx|p12|sql|dmp|env)$`)

// checkSensitiveFile flags directly accessible files that commonly hold
// credentials, backups, or archives (e.g. KeePass databases, private keys).
func checkSensitiveFile(ex *Exchange) *models.Signal {
	if ex.Status != 200 {
		return nil
	}
	if !sensitiveFileRx.MatchString(ex.Path) {
		return nil
	}
	ct := ctOf(ex)
	if strings.Contains(ct, "html") || strings.Contains(ct, "json") {
		return nil // SPA fallback or API response, not the file itself
	}
	if len(ex.RespBody) == 0 {
		return nil
	}
	sev := "medium"
	if credentialFileRx.MatchString(ex.Path) {
		sev = "high"
	}
	sig := signalFrom(ex, "sensitive-file",
		"Sensitive file directly accessible", sev, "high")
	sig.Evidence["url"] = ex.URL
	sig.Evidence["content_type"] = ex.RespHeaders.Get("Content-Type")
	sig.Evidence["size_bytes"] = len(ex.RespBody)
	sig.Explanation = "The response serves " + ex.Path + " (" + ct + ", " +
		fmt.Sprintf("%d bytes) with HTTP 200. Files of this type typically hold credentials (KeePass databases, private keys, SQL dumps) or sensitive backups and archives; unauthenticated download enables offline password attacks and data disclosure.", len(ex.RespBody))
	sig.Remediation = "Move secrets out of the web root, deny access to credential/backup file types, and serve the directory with an allow-list. Revoke and rotate any exposed material."
	return sig
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Credential disclosure patterns. Compound patterns (connection strings,
// cloud keys, private keys) are high signal; the generic key=value pattern
// is gated on placeholder/code-sample exclusions to avoid flagging
// documentation text.
var jdbcCredRx = regexp.MustCompile(`(?i)jdbc:[a-z0-9]+://[^\s"']*(?:user|username|uid)=[^\s&"'<>]+&?(?:password|passwd|pwd)=[^\s&"'<>]+`)

var dbUrlCredRx = regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|rabbitmq|sqlserver|oracle|mssql|ftp)://[^\s"'<>]*:[^@\s"'<>]+@`)

var awsKeyRx = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)

var privKeyRx = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)

var genericCredRx = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api_key|apikey|api-key|client_secret|access_token|auth_token)\s*=\s*([^\s&"'<>]{4,})`)

var credPlaceholderValues = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true,
	"username": true, "user": true, "xxxx": true, "xxx": true,
	"1234": true, "123456": true, "********": true, "*****": true,
	"redacted": true, "null": true, "false": true, "true": true,
	"undefined": true, "example": true, "changeme": true,
}

func looksLikeCredentialValue(v string) bool {
	lower := strings.ToLower(v)
	if credPlaceholderValues[lower] {
		return false
	}
	for _, c := range []byte("();<>{}[]") {
		if strings.ContainsRune(lower, rune(c)) {
			return false // code sample or markup, not a plain credential value
		}
	}
	return true
}

// checkCredentialDisclosure flags credentials embedded in response bodies:
// database connection strings, cloud keys, private keys, and generic
// password/secret key=value assignments.
func checkCredentialDisclosure(ex *Exchange) *models.Signal {
	body := string(ex.RespBody)
	var leaks []string
	sev, conf := "", ""

	switch {
	case jdbcCredRx.MatchString(body):
		m := jdbcCredRx.FindString(body)
		leaks = append(leaks, "database connection string with credentials: "+m)
		sev, conf = "high", "high"
	case dbUrlCredRx.MatchString(body):
		m := dbUrlCredRx.FindString(body)
		leaks = append(leaks, "URL with embedded credentials: "+m)
		sev, conf = "high", "high"
	case awsKeyRx.MatchString(body):
		leaks = append(leaks, "cloud access key: "+awsKeyRx.FindString(body))
		sev, conf = "high", "high"
	case privKeyRx.MatchString(body):
		leaks = append(leaks, "private key material: "+privKeyRx.FindString(body))
		sev, conf = "high", "high"
	default:
		for _, m := range genericCredRx.FindAllStringSubmatch(body, -1) {
			if !looksLikeCredentialValue(m[2]) {
				continue
			}
			leaks = append(leaks, m[1]+"="+m[2])
			sev, conf = "medium", "medium"
		}
		if len(leaks) == 0 {
			return nil
		}
	}
	sig := signalFrom(ex, "credential-disclosure",
		"Credentials disclosed in response body", sev, conf)
	sig.Evidence["leaks"] = leaks
	sig.Evidence["url"] = ex.URL
	sig.Explanation = "The response body contains credential material: " +
		strings.Join(leaks, "; ") + ". Anyone who can read this response (users, proxies, logs, bots) obtains secrets that can unlock data or services."
	sig.Remediation = "Never embed credentials in client-visible responses. Redact error messages, move secrets to environment variables or a vault, and rotate any credentials that were exposed."
	return sig
}

// passiveChecks is the full passive check pipeline.
var passiveChecks = []func(*Exchange) *models.Signal{
	checkMissingSecurityHeaders,
	checkCookieFlags,
	checkCORS,
	checkInfoDisclosure,
	checkSensitiveURLParams,
	checkMixedContent,
	checkOpenRedirect,
	checkCSRF,
	checkCacheControl,
	checkHSTS,
	checkSSRFParam,
	checkSensitiveFile,
	checkCredentialDisclosure,
}
