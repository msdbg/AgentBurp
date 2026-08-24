package auth

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

type LoginResult struct {
	SessionID  string               `json:"session_id"`
	Profile    string               `json:"profile"`
	RequestID  string               `json:"request_id,omitempty"`
	ResponseID string               `json:"response_id,omitempty"`
	Status     int                  `json:"status"`
	Cookies    []models.CookieEntry `json:"cookies"`
	Headers    []models.Header      `json:"headers"`
	Tokens     map[string]string    `json:"tokens"`
	TimeMs     int64                `json:"time_ms"`
	Warning    string               `json:"warning,omitempty"`
}

type LoginRunner struct {
	*SessionStore
	db        *sql.DB
	projectID string
	client    *http.Client
	jar       http.CookieJar
}

func NewLoginRunner(db *core.DB, projectID string) *LoginRunner {
	jar, _ := cookiejar.New(nil)
	return &LoginRunner{
		SessionStore: NewSessionStore(db, projectID),
		db:           db.Conn(),
		projectID:    projectID,
		jar:          jar,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func (r *LoginRunner) Login(projectName string, profile *AuthProfile) (*LoginResult, error) {
	p := profile.Substitute()

	if p.Type == "bearer" || p.Type == "basic" || p.Type == "header" {
		return r.staticSession(projectName, p)
	}

	reqBody, contentType, err := buildLoginBody(p)
	if err != nil {
		return nil, err
	}

	if p.Type == "form_login" && p.CSRF.Field != "" {
		token, err := r.fetchCSRFToken(p)
		if err != nil {
			return nil, err
		}
		form, _ := url.ParseQuery(string(reqBody))
		form.Set(p.CSRF.Field, token)
		reqBody = []byte(form.Encode())
	}

	method := p.Method
	if method == "" {
		method = http.MethodPost
	}

	httpReq, err := http.NewRequest(strings.ToUpper(method), p.URL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Set("Accept", "application/json, text/html, */*")
	for k, v := range p.Headers {
		httpReq.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	respBody, _ := io.ReadAll(resp.Body)

	reqID, respID := r.saveExchange(httpReq, reqBody, resp, respBody, p.URL)

	sess := &models.Session{
		ID:            core.NewID("sess"),
		ProjectID:     r.projectID,
		Name:          p.Name,
		Role:          profileRole(p),
		Tokens:        map[string]string{},
		AuthProfileID: p.Name,
		CreatedAt:     core.TimestampNow(),
		UpdatedAt:     core.TimestampNow(),
	}

	if p.Capture.Cookies {
		r.SetCookies(sess, resp.Header.Values("Set-Cookie"))
		if u, err := url.Parse(p.URL); err == nil {
			for _, c := range r.jar.Cookies(u) {
				r.SetCookies(sess, []string{c.Name + "=" + c.Value})
			}
		}
	}

	if len(p.Headers) > 0 {
		r.SetHeaders(sess, p.Headers)
	}

	for _, h := range p.Capture.Headers {
		if v := resp.Header.Get(h); v != "" {
			tokens := map[string]string{h: v}
			if strings.EqualFold(h, "Authorization") || strings.Contains(strings.ToLower(h), "token") {
				tokens["Authorization"] = v
			}
			r.SetTokens(sess, tokens)
		}
	}

	tokens := extractTokensFromBody(respBody, p.TokenFields)
	if p.TokenFromHeader != "" {
		if v := resp.Header.Get(p.TokenFromHeader); v != "" {
			tokens["Authorization"] = v
		}
	}
	if len(tokens) > 0 {
		r.SetTokens(sess, tokens)
	}

	_, err = r.db.Exec(`DELETE FROM sessions WHERE project_id = ? AND name = ?`, r.projectID, p.Name)
	if err != nil {
		return nil, fmt.Errorf("replace old session: %w", err)
	}
	cJSON, _ := json.Marshal(sess.Cookies)
	hJSON, _ := json.Marshal(sess.Headers)
	tJSON, _ := json.Marshal(sess.Tokens)
	_, err = r.db.Exec(`
		INSERT INTO sessions (id, project_id, name, role, cookies_json, headers_json, tokens_json, auth_profile_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, r.projectID, p.Name, sess.Role,
		string(cJSON), string(hJSON), string(tJSON), p.Name,
		sess.CreatedAt, sess.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}

	result := &LoginResult{
		SessionID:  sess.ID,
		Profile:    p.Name,
		RequestID:  reqID,
		ResponseID: respID,
		Status:     resp.StatusCode,
		Cookies:    sess.Cookies,
		Headers:    sess.Headers,
		Tokens:     sess.Tokens,
		TimeMs:     elapsed,
	}

	if resp.StatusCode >= 400 || looksLikeLoginPage(respBody, resp.Header.Get("Content-Type")) {
		result.Warning = "login may have failed: the response re-renders the login form (status " +
			fmt.Sprint(resp.StatusCode) + "); the captured session may not authenticate"
	}
	return result, nil
}

func looksLikeLoginPage(body []byte, contentType string) bool {
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return false
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "<form") &&
		strings.Contains(lower, "password") &&
		(strings.Contains(lower, "login") || strings.Contains(lower, "signin"))
}

func (r *LoginRunner) staticSession(projectName string, p *AuthProfile) (*LoginResult, error) {
	sess := &models.Session{
		ID:            core.NewID("sess"),
		ProjectID:     r.projectID,
		Name:          p.Name,
		Role:          profileRole(p),
		Tokens:        map[string]string{},
		AuthProfileID: p.Name,
		CreatedAt:     core.TimestampNow(),
		UpdatedAt:     core.TimestampNow(),
	}

	switch p.Type {
	case "bearer":
		sess.Tokens["Authorization"] = "Bearer " + p.Token
	case "basic":
		basic := base64Encode(p.Username + ":" + p.Password)
		sess.Tokens["Authorization"] = "Basic " + basic
	case "header":
		r.SetHeaders(sess, p.Headers)
	}
	if len(p.Headers) > 0 {
		r.SetHeaders(sess, p.Headers)
	}

	cJSON, _ := json.Marshal(sess.Cookies)
	hJSON, _ := json.Marshal(sess.Headers)
	tJSON, _ := json.Marshal(sess.Tokens)
	_, err := r.db.Exec(`
		INSERT INTO sessions (id, project_id, name, role, cookies_json, headers_json, tokens_json, auth_profile_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, r.projectID, p.Name, sess.Role,
		string(cJSON), string(hJSON), string(tJSON), p.Name,
		sess.CreatedAt, sess.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}

	return &LoginResult{
		SessionID: sess.ID,
		Profile:   p.Name,
		Status:    0,
		Cookies:   sess.Cookies,
		Headers:   sess.Headers,
		Tokens:    sess.Tokens,
	}, nil
}

func (r *LoginRunner) fetchCSRFToken(p *AuthProfile) (string, error) {
	tokenURL := p.CSRF.URL
	if tokenURL == "" {
		tokenURL = p.URL
	}
	req, err := http.NewRequest(http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("build csrf pre-fetch: %w", err)
	}
	req.Header.Set("Accept", "text/html, */*")
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("csrf pre-fetch failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	r.saveExchange(req, nil, resp, body, tokenURL)

	token := extractHiddenField(body, p.CSRF.Field)
	if token == "" {
		return "", fmt.Errorf(
			"csrf field %q not found in %s — check the profile's csrf.field/csrf.url", p.CSRF.Field, tokenURL)
	}
	return token, nil
}

func extractHiddenField(body []byte, field string) string {
	nameRe := regexp.MustCompile(`(?is)\bname\s*=\s*["']?` + regexp.QuoteMeta(field) + `["']?(?:\s|/?>)`)
	tagRe := regexp.MustCompile(`(?is)<input\b[^>]*>`)
	valueRe := regexp.MustCompile(`(?is)\bvalue\s*=\s*["']?([^"'\s>]*)["']?`)
	for _, tag := range tagRe.FindAll(body, -1) {
		if !nameRe.Match(tag) {
			continue
		}
		if m := valueRe.FindSubmatch(tag); len(m) > 1 {
			return string(m[1])
		}
	}
	return ""
}

func (r *LoginRunner) saveExchange(httpReq *http.Request, reqBody []byte, resp *http.Response, respBody []byte, rawURL string) (string, string) {
	u, _ := url.Parse(rawURL)
	host := u.Hostname()
	portNum := 80
	if u.Port() != "" {
		fmt.Sscanf(u.Port(), "%d", &portNum)
	} else if u.Scheme == "https" {
		portNum = 443
	}

	reqID := core.NewID("req")
	now := core.TimestampNow()

	reqHeaders := make([]models.Header, 0, len(httpReq.Header))
	for k, vals := range httpReq.Header {
		for _, v := range vals {
			reqHeaders = append(reqHeaders, models.Header{Name: k, Value: v})
		}
	}
	hJSON, _ := json.Marshal(reqHeaders)

	r.db.Exec(`
		INSERT INTO requests
		  (id, project_id, source, method, url, host, port, scheme, path, query_string, headers_json, body_blob, created_at)
		VALUES (?, ?, 'auth', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reqID, r.projectID, httpReq.Method, rawURL, host, portNum, u.Scheme,
		u.Path, u.RawQuery, string(hJSON), reqBody, now,
	)
	context.ExtractEndpoint(r.db, r.projectID, reqID, host, httpReq.Method, u.Path, u.RawQuery, httpReq.Header, reqBody)
	ct := resp.Header.Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	context.UpdateEndpointResponse(r.db, reqID, resp.StatusCode, ct)

	respID := core.NewID("resp")
	respHeaders := make([]models.Header, 0, len(resp.Header))
	for k, vals := range resp.Header {
		for _, v := range vals {
			respHeaders = append(respHeaders, models.Header{Name: k, Value: v})
		}
	}
	rhJSON, _ := json.Marshal(respHeaders)
	r.db.Exec(`
		INSERT INTO responses
		  (id, request_id, status_code, reason, headers_json, body_blob, content_type, length_bytes, created_at)
		VALUES (?, ?, ?, '', ?, ?, ?, ?, ?)`,
		respID, reqID, resp.StatusCode, string(rhJSON), respBody, ct, len(respBody), now,
	)

	return reqID, respID
}

func buildLoginBody(p *AuthProfile) ([]byte, string, error) {
	switch p.Type {
	case "json_login":
		b, err := json.Marshal(p.Body)
		if err != nil {
			return nil, "", fmt.Errorf("marshal login body: %w", err)
		}
		if len(b) == 0 {
			b = []byte("{}")
		}
		return b, "application/json", nil
	case "form_login":
		form := url.Values{}
		for k, v := range p.Form {
			form.Set(k, v)
		}
		if len(form) == 0 {
			for k, v := range p.Body {
				form.Set(k, fmt.Sprintf("%v", v))
			}
		}
		if form.Encode() == "" {
			return nil, "", fmt.Errorf("form_login profile %q: no form fields (use `form:` or `body:`)", p.Name)
		}
		return []byte(form.Encode()), "application/x-www-form-urlencoded", nil
	default:
		return nil, "", fmt.Errorf("unsupported login type %q", p.Type)
	}
}

func extractTokensFromBody(body []byte, tokenFields []string) map[string]string {
	if len(body) == 0 || len(tokenFields) == 0 {
		return nil
	}
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil
	}
	tokens := map[string]string{}
	for _, path := range tokenFields {
		if v, ok := lookupPath(obj, path); ok && v != "" {
			key := path
			if strings.Contains(path, ".") {
				key = path[strings.LastIndex(path, ".")+1:]
			}
			if _, exists := tokens[key]; !exists {
				tokens[key] = v
			}
			if _, exists := tokens["Authorization"]; !exists {
				if strings.EqualFold(key, "access_token") || strings.EqualFold(key, "id_token") ||
					strings.EqualFold(key, "refresh_token") || strings.EqualFold(key, "token") {
					tokens["Authorization"] = "Bearer " + v
				}
			}
		}
	}
	return tokens
}

func lookupPath(obj interface{}, path string) (string, bool) {
	cur := obj
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur, ok = m[seg]
		if !ok {
			return "", false
		}
	}
	if s, ok := cur.(string); ok {
		return s, true
	}
	if f, ok := cur.(float64); ok {
		return fmt.Sprintf("%v", f), true
	}
	return "", false
}

func profileRole(p *AuthProfile) string {
	if p.Username != "" {
		return p.Username
	}
	return "authenticated"
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
