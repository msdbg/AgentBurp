package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

type SessionStore struct {
	db        *sql.DB
	projectID string
}

func NewSessionStore(db *core.DB, projectID string) *SessionStore {
	return &SessionStore{db: db.Conn(), projectID: projectID}
}

func (s *SessionStore) Create(name, role string) (string, error) {
	id := core.NewID("sess")
	now := core.TimestampNow()
	_, err := s.db.Exec(`
		INSERT INTO sessions (id, project_id, name, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id, s.projectID, name, role, now, now,
	)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

func (s *SessionStore) Get(sessID string) (*models.Session, error) {
	row := s.db.QueryRow(`
		SELECT id, project_id, name, role, cookies_json, headers_json, tokens_json,
		       COALESCE(auth_profile_id,''), created_at, updated_at
		FROM sessions WHERE (id = ? OR name = ?) AND project_id = ?`, sessID, sessID, s.projectID)
	return scanSession(row)
}

func (s *SessionStore) List() ([]*models.Session, error) {
	rows, err := s.db.Query(`
		SELECT id, project_id, name, role, cookies_json, headers_json, tokens_json,
		       COALESCE(auth_profile_id,''), created_at, updated_at
		FROM sessions WHERE project_id = ? ORDER BY created_at DESC`, s.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SessionStore) Delete(sessID string, projectName string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ? AND project_id = ?`, sessID, s.projectID)
	if err != nil {
		return err
	}
	cfg, err := core.LoadConfig(projectName)
	if err == nil && cfg.ActiveSessionID == sessID {
		cfg.ActiveSessionID = ""
		_ = core.SaveConfig(projectName, cfg)
	}
	return nil
}

func (s *SessionStore) Save(sess *models.Session) error {
	cJSON, _ := json.Marshal(sess.Cookies)
	hJSON, _ := json.Marshal(sess.Headers)
	tJSON, _ := json.Marshal(sess.Tokens)
	now := core.TimestampNow()
	_, err := s.db.Exec(`
		UPDATE sessions
		SET cookies_json = ?, headers_json = ?, tokens_json = ?, updated_at = ?
		WHERE id = ? AND project_id = ?`,
		string(cJSON), string(hJSON), string(tJSON), now, sess.ID, s.projectID,
	)
	return err
}

func SetActiveSession(projectName, sessID string) error {
	cfg, err := core.LoadConfig(projectName)
	if err != nil {
		return err
	}
	cfg.ActiveSessionID = sessID
	return core.SaveConfig(projectName, cfg)
}

func ActiveSessionID(projectName string) string {
	cfg, err := core.LoadConfig(projectName)
	if err != nil {
		return ""
	}
	return cfg.ActiveSessionID
}

func (s *SessionStore) SetCookies(sess *models.Session, setCookieHeaders []string) int {
	added := 0
	for _, sc := range setCookieHeaders {
		parts := strings.Split(sc, ";")
		if len(parts) == 0 {
			continue
		}
		kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		entry := models.CookieEntry{
			Name:  name,
			Value: strings.TrimSpace(kv[1]),
		}
		for _, attr := range parts[1:] {
			attr = strings.TrimSpace(attr)
			akv := strings.SplitN(attr, "=", 2)
			ak := strings.ToLower(akv[0])
			av := ""
			if len(akv) == 2 {
				av = akv[1]
			}
			switch ak {
			case "domain":
				entry.Domain = av
			case "path":
				entry.Path = av
			case "secure":
				entry.Secure = true
			case "httponly":
				entry.HttpOnly = true
			case "samesite":
				entry.SameSite = av
			case "expires":
				entry.Expires = av
			}
		}
		replaced := false
		for i, c := range sess.Cookies {
			if c.Name == name {
				sess.Cookies[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			sess.Cookies = append(sess.Cookies, entry)
			added++
		}
	}
	return added
}

func (s *SessionStore) SetTokens(sess *models.Session, tokens map[string]string) {
	if sess.Tokens == nil {
		sess.Tokens = map[string]string{}
	}
	for k, v := range tokens {
		sess.Tokens[k] = v
	}
}

func (s *SessionStore) SetHeaders(sess *models.Session, headers map[string]string) {
	for k, v := range headers {
		updated := false
		for i, h := range sess.Headers {
			if strings.EqualFold(h.Name, k) {
				sess.Headers[i].Value = v
				updated = true
				break
			}
		}
		if !updated {
			sess.Headers = append(sess.Headers, models.Header{Name: k, Value: v})
		}
	}
}

func (s *SessionStore) ApplyToRequest(sess *models.Session, headers []models.Header) []models.Header {
	if sess == nil {
		return headers
	}

	for _, sh := range sess.Headers {
		if strings.EqualFold(sh.Name, "Cookie") {
			continue
		}
		updated := false
		for i := range headers {
			if strings.EqualFold(headers[i].Name, sh.Name) {
				headers[i].Value = sh.Value
				updated = true
				break
			}
		}
		if !updated {
			headers = append(headers, models.Header{Name: sh.Name, Value: sh.Value})
		}
	}

	if len(sess.Tokens) > 0 {
		if tok := sess.Tokens["Authorization"]; tok != "" {
			headers = upsertHeader(headers, "Authorization", tok)
		}
	}

	if len(sess.Cookies) > 0 {
		cookieVals := make([]string, 0, len(sess.Cookies))
		for _, c := range sess.Cookies {
			cookieVals = append(cookieVals, c.Name+"="+c.Value)
		}
		headers = upsertHeader(headers, "Cookie", strings.Join(cookieVals, "; "))
	}

	return headers
}

func (s *SessionStore) Active(projectName string) (*models.Session, error) {
	id := ActiveSessionID(projectName)
	if id == "" {
		return nil, nil
	}
	sess, err := s.Get(id)
	if err != nil {
		return nil, fmt.Errorf("active session %s: %w", id, err)
	}
	return sess, nil
}

func (s *SessionStore) CookieHeaderValue(sess *models.Session) string {
	if sess == nil || len(sess.Cookies) == 0 {
		return ""
	}
	vals := make([]string, 0, len(sess.Cookies))
	for _, c := range sess.Cookies {
		vals = append(vals, c.Name+"="+c.Value)
	}
	return strings.Join(vals, "; ")
}

func upsertHeader(headers []models.Header, name, value string) []models.Header {
	for i := range headers {
		if strings.EqualFold(headers[i].Name, name) {
			headers[i].Value = value
			return headers
		}
	}
	return append(headers, models.Header{Name: name, Value: value})
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSession(row rowScanner) (*models.Session, error) {
	var s models.Session
	var cookiesJSON, headersJSON, tokensJSON string
	if err := row.Scan(
		&s.ID, &s.ProjectID, &s.Name, &s.Role,
		&cookiesJSON, &headersJSON, &tokensJSON,
		&s.AuthProfileID, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}
	json.Unmarshal([]byte(cookiesJSON), &s.Cookies)
	json.Unmarshal([]byte(headersJSON), &s.Headers)
	json.Unmarshal([]byte(tokensJSON), &s.Tokens)
	if s.Tokens == nil {
		s.Tokens = map[string]string{}
	}
	return &s, nil
}
