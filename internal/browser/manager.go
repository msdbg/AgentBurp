package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/msdbg/AgentBurp/internal/core"
)

type Session struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	Name         string `json:"name,omitempty"`
	Status       string `json:"status"`
	CurrentURL   string `json:"current_url,omitempty"`
	Profile      string `json:"profile"`
	BrowserPID   int    `json:"browser_pid,omitempty"`
	CreatedAt    string `json:"created_at"`
	LastActivity string `json:"last_activity,omitempty"`
}

type Manager struct {
	db        *core.DB
	projectID string
	mu        sync.Mutex
	browsers  map[string]*browserInstance
}

type browserInstance struct {
	browser *rod.Browser
	page    *rod.Page
	profile string
	url     string
}

func NewManager(db *core.DB, projectID string) *Manager {
	return &Manager{
		db:        db,
		projectID: projectID,
		browsers:  map[string]*browserInstance{},
	}
}

func (m *Manager) Open(ctx context.Context, targetURL, profile string, headed, waitForHuman bool, name string) (*Session, error) {
	if targetURL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if _, err := url.ParseRequestURI(targetURL); err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", targetURL, err)
	}
	if profile == "" {
		profile = "stealth"
	}
	id := core.NewID("bses")
	now := core.TimestampNow()
	extra, _ := json.Marshal(map[string]interface{}{"headed": headed, "wait_for_human": waitForHuman})

	_, err := m.db.Conn().Exec(
		`INSERT INTO browser_sessions (id, project_id, name, status, current_url, profile, created_at, last_activity, extra_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, m.projectID, name, "open", targetURL, profile, now, now, string(extra),
	)
	if err != nil {
		return nil, fmt.Errorf("create browser_session: %w", err)
	}

	inst, launchErr := m.launchBrowser(ctx, targetURL, profile, headed)
	if launchErr != nil {
		m.db.Conn().Exec(`UPDATE browser_sessions SET status = ?, extra_json = ? WHERE id = ?`,
			"error",
			fmt.Sprintf(`{"error":%q,"headed":%v}`, launchErr.Error(), headed),
			id,
		)
		return &Session{
			ID: id, ProjectID: m.projectID, Name: name,
			Status: "error", CurrentURL: targetURL, Profile: profile,
			CreatedAt: now, LastActivity: now,
		}, nil
	}

	finalURL := targetURL
	var snapshotCookies []map[string]string
	var snapshotStorage map[string]string
	if inst != nil && inst.page != nil {
		if info, err := inst.page.Info(); err == nil && info.URL != "" {
			finalURL = info.URL
		}
		if cookies, err := inst.page.Cookies([]string{}); err == nil {
			for _, c := range cookies {
				snapshotCookies = append(snapshotCookies, map[string]string{
					"name": c.Name, "value": c.Value, "domain": c.Domain, "path": c.Path,
					"sameSite": string(c.SameSite), "expires": fmt.Sprint(c.Expires),
				})
			}
		}
		if val, err := inst.page.Eval(`() => { const out={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i); out[k]=localStorage.getItem(k);} return out; }`); err == nil {
			var tmp map[string]string
			if raw, ok := val.Value.MarshalJSON(); ok == nil {
				json.Unmarshal(raw, &tmp)
				snapshotStorage = tmp
			}
		}
	}

	snapshot := map[string]interface{}{
		"headed":         headed,
		"wait_for_human": waitForHuman,
		"final_url":      finalURL,
		"cookies":        snapshotCookies,
		"storage":        snapshotStorage,
		"captured_at":    core.TimestampNow(),
	}
	snapJSON, _ := json.Marshal(snapshot)
	m.db.Conn().Exec(`UPDATE browser_sessions SET current_url = ?, extra_json = ?, last_activity = ? WHERE id = ?`,
		finalURL, string(snapJSON), core.TimestampNow(), id)

	m.mu.Lock()
	m.browsers[id] = inst
	m.mu.Unlock()

	if waitForHuman {
		m.db.Conn().Exec(`UPDATE browser_sessions SET status = ? WHERE id = ?`, "waiting_human", id)
		return &Session{
			ID: id, ProjectID: m.projectID, Name: name,
			Status: "waiting_human", CurrentURL: finalURL, Profile: profile,
			CreatedAt: now, LastActivity: now,
		}, nil
	}

	return &Session{
		ID: id, ProjectID: m.projectID, Name: name,
		Status: "open", CurrentURL: finalURL, Profile: profile,
		CreatedAt: now, LastActivity: now,
	}, nil
}

func (m *Manager) launchBrowser(ctx context.Context, targetURL, profile string, headed bool) (*browserInstance, error) {
	lc := launcher.New().
		NoSandbox(true).
		Set("--disable-gpu").
		Set("--disable-dev-shm-usage")

	if headed {
		lc = lc.Headless(false)
	} else {
		lc = lc.Headless(true)
	}

	controlURL, err := lc.Launch()
	if err != nil {
		return nil, fmt.Errorf("launch chrome: %w (install Chrome or use --headed with visible browser)", err)
	}
	browser := rod.New().ControlURL(controlURL).Context(ctx)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("connect to browser: %w", err)
	}

	var page *rod.Page
	if profile == "stealth" {
		page, err = stealth.Page(browser)
	} else {
		page, err = browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	}
	if err != nil {
		browser.Close()
		return nil, err
	}

	page.MustSetViewport(1280, 800, 1, false)

	if err := page.Navigate(targetURL); err != nil {
		_ = err
	}
	page.Timeout(15 * time.Second)
	_ = page.WaitLoad()

	if profile == "stealth" {
		time.Sleep(2 * time.Second)
	}

	currentURL := targetURL
	if info, err := page.Info(); err == nil && info.URL != "" {
		currentURL = info.URL
	}

	return &browserInstance{browser: browser, page: page, profile: profile, url: currentURL}, nil
}

func (m *Manager) List() ([]*Session, error) {
	rows, err := m.db.Conn().Query(
		`SELECT id, project_id, COALESCE(name,''), status, COALESCE(current_url,''), profile, COALESCE(browser_pid,0), created_at, COALESCE(last_activity,'') FROM browser_sessions WHERE project_id = ? ORDER BY created_at DESC`, m.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		var s Session
		var pid int
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.Name, &s.Status, &s.CurrentURL, &s.Profile, &pid, &s.CreatedAt, &s.LastActivity); err != nil {
			return nil, err
		}
		s.BrowserPID = pid
		out = append(out, &s)
	}
	return out, rows.Err()
}

func (m *Manager) Get(identifier string) (*Session, error) {
	var s Session
	var pid int
	err := m.db.Conn().QueryRow(
		`SELECT id, project_id, COALESCE(name,''), status, COALESCE(current_url,''), profile, COALESCE(browser_pid,0), created_at, COALESCE(last_activity,'') FROM browser_sessions WHERE (id = ? OR name = ?) AND project_id = ?`,
		identifier, identifier, m.projectID,
	).Scan(&s.ID, &s.ProjectID, &s.Name, &s.Status, &s.CurrentURL, &s.Profile, &pid, &s.CreatedAt, &s.LastActivity)
	if err != nil {
		return nil, fmt.Errorf("browser session %q not found", identifier)
	}
	s.BrowserPID = pid
	return &s, nil
}

func (m *Manager) Status(identifier string) (*Session, error) {
	s, err := m.Get(identifier)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	if ok && inst.page != nil {
		if info, err := inst.page.Info(); err == nil && info.URL != "" {
			s.CurrentURL = info.URL
		}
	}
	return s, nil
}

func (m *Manager) Close(identifier string) error {
	s, err := m.Get(identifier)
	if err != nil {
		return err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	if ok {
		if inst.browser != nil {
			inst.browser.Close()
		}
		delete(m.browsers, s.ID)
	}
	m.mu.Unlock()
	_, err = m.db.Conn().Exec(`UPDATE browser_sessions SET status = ?, last_activity = ? WHERE id = ?`, "closed", core.TimestampNow(), s.ID)
	return err
}

func (m *Manager) Cookies(identifier string) ([]map[string]string, error) {
	s, err := m.Get(identifier)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	if ok && inst.page != nil {
		cookies, err := inst.page.Cookies([]string{})
		if err == nil {
			var out []map[string]string
			for _, c := range cookies {
				out = append(out, map[string]string{
					"name": c.Name, "value": c.Value, "domain": c.Domain, "path": c.Path,
					"sameSite": string(c.SameSite), "expires": fmt.Sprint(c.Expires),
				})
			}
			return out, nil
		}
	}
	var extraJSON string
	err = m.db.Conn().QueryRow(`SELECT COALESCE(extra_json,'{}') FROM browser_sessions WHERE id = ?`, s.ID).Scan(&extraJSON)
	if err == nil {
		var snap map[string]interface{}
		if json.Unmarshal([]byte(extraJSON), &snap) == nil {
			if raw, ok := snap["cookies"]; ok {

				if arr, ok := raw.([]interface{}); ok {
					var out []map[string]string
					for _, item := range arr {
						if mm, ok := item.(map[string]interface{}); ok {
							entry := map[string]string{}
							for k, v := range mm {
								entry[k] = fmt.Sprint(v)
							}
							out = append(out, entry)
						}
					}
					return out, nil
				}
			}
		}
	}
	return []map[string]string{}, nil
}

func (m *Manager) Storage(identifier string, storageType string) (map[string]string, error) {
	s, err := m.Get(identifier)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	if ok && inst.page != nil {
		var js string
		switch storageType {
		case "sessionStorage":
			js = `() => { const out={}; for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i); out[k]=sessionStorage.getItem(k);} return out; }`
		default:
			js = `() => { const out={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i); out[k]=localStorage.getItem(k);} return out; }`
		}
		val, err := inst.page.Eval(js)
		if err == nil {
			var out map[string]string
			if raw, ok := val.Value.MarshalJSON(); ok == nil {
				json.Unmarshal(raw, &out)
			}
			if out != nil {
				return out, nil
			}
		}
	}
	var extraJSON string
	m.db.Conn().QueryRow(`SELECT COALESCE(extra_json,'{}') FROM browser_sessions WHERE id = ?`, s.ID).Scan(&extraJSON)
	if extraJSON != "" {
		var snap map[string]interface{}
		if json.Unmarshal([]byte(extraJSON), &snap) == nil {
			if raw, ok := snap["storage"]; ok {
				if mm, ok := raw.(map[string]interface{}); ok {
					out := map[string]string{}
					for k, v := range mm {
						out[k] = fmt.Sprint(v)
					}
					return out, nil
				}
			}
		}
	}
	return map[string]string{}, nil
}

func (m *Manager) Execute(identifier, js string) (interface{}, error) {
	s, err := m.Get(identifier)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	needClose := false
	if !ok || inst.page == nil {

		target := s.CurrentURL
		if target == "" {
			target = "about:blank"
		}
		tmp, err := m.launchBrowser(context.Background(), target, s.Profile, false)
		if err != nil {
			return nil, fmt.Errorf("browser session %q has no active page and ephemeral launch failed: %w (try browser open %q again)", identifier, err, target)
		}
		inst = tmp
		needClose = true
	}
	defer func() {
		if needClose && inst != nil && inst.browser != nil {
			inst.browser.Close()
		}
	}()
	trimmed := strings.TrimSpace(js)
	if strings.HasPrefix(trimmed, "return ") {
		js = fmt.Sprintf(`() => { %s }`, trimmed)
	} else if !strings.HasPrefix(trimmed, "()") && !strings.HasPrefix(trimmed, "async") && !strings.HasPrefix(trimmed, "function") {

		js = fmt.Sprintf(`() => %s`, trimmed)
	}
	val, err := inst.page.Eval(js)
	if err != nil {
		return nil, fmt.Errorf("execute js: %w", err)
	}
	var result interface{}
	if raw, ok := val.Value.MarshalJSON(); ok == nil {
		json.Unmarshal(raw, &result)
	} else {
		result = val.Value.String()
	}
	m.db.Conn().Exec(`UPDATE browser_sessions SET last_activity = ? WHERE id = ?`, core.TimestampNow(), s.ID)
	return result, nil
}

func (m *Manager) ExecuteFile(identifier, jsContent string) (interface{}, error) {
	return m.Execute(identifier, jsContent)
}

func (m *Manager) WaitForSelector(identifier, selector string, timeout time.Duration) error {
	s, err := m.Get(identifier)
	if err != nil {
		return err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	if !ok || inst.page == nil {
		return fmt.Errorf("browser session %q has no active page", identifier)
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	inst.page.Context(ctx)
	defer inst.page.Context(context.Background())

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		exists, _, err := inst.page.Has(selector)
		if err == nil && exists {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for selector %q", selector)
		default:
		}
	}
	return fmt.Errorf("timeout waiting for selector %q after %s", selector, timeout)
}

func (m *Manager) WaitForURL(identifier, contains string, timeout time.Duration) error {
	s, err := m.Get(identifier)
	if err != nil {
		return err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	if !ok || inst.page == nil {
		return fmt.Errorf("no active page")
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := inst.page.Info(); err == nil && strings.Contains(info.URL, contains) {
			m.db.Conn().Exec(`UPDATE browser_sessions SET current_url = ?, last_activity = ? WHERE id = ?`, info.URL, core.TimestampNow(), s.ID)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for url containing %q", contains)
}

func (m *Manager) WaitForNetworkIdle(identifier string, timeout time.Duration) error {
	s, err := m.Get(identifier)
	if err != nil {
		return err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	if !ok || inst.page == nil {
		return fmt.Errorf("no active page")
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	inst.page.Timeout(timeout)
	return inst.page.WaitIdle(time.Second)
}

func (m *Manager) Fetch(identifier, method, urlStr, body string, headers map[string]string, timeout time.Duration) (map[string]interface{}, error) {
	s, err := m.Get(identifier)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	inst, ok := m.browsers[s.ID]
	m.mu.Unlock()
	needClose := false
	if !ok || inst.page == nil {
		target := s.CurrentURL
		if target == "" {
			target = urlStr
		}
		tmp, err := m.launchBrowser(context.Background(), target, s.Profile, false)
		if err != nil {
			return nil, fmt.Errorf("browser session %q has no active page and ephemeral launch failed: %w", identifier, err)
		}
		inst = tmp
		needClose = true
		defer func() {
			if needClose && inst != nil && inst.browser != nil {
				inst.browser.Close()
			}
		}()
	}
	if method == "" {
		method = "GET"
	}
	hJSON, _ := json.Marshal(headers)
	js := fmt.Sprintf(`async () => {
		const res = await fetch(%q, {
			method: %q,
			headers: %s,
			body: %s,
			credentials: 'include'
		});
		const text = await res.text();
		const headers = {};
		res.headers.forEach((v,k) => headers[k]=v);
		return {status: res.status, headers, body: text, url: res.url};
	}`, urlStr, method, string(hJSON), bodyJSON(body, method))

	val, err := inst.page.Eval(js)
	if err != nil {
		return nil, fmt.Errorf("browser fetch: %w", err)
	}
	var result map[string]interface{}
	if raw, ok := val.Value.MarshalJSON(); ok == nil {
		json.Unmarshal(raw, &result)
	}
	m.db.Conn().Exec(`UPDATE browser_sessions SET last_activity = ? WHERE id = ?`, core.TimestampNow(), s.ID)
	return result, nil
}

func bodyJSON(body, method string) string {
	if body == "" || method == "GET" || method == "HEAD" {
		return "undefined"
	}
	b, _ := json.Marshal(body)
	return string(b)
}

func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, inst := range m.browsers {
		if inst.browser != nil {
			inst.browser.Close()
		}
		delete(m.browsers, id)
	}
}
