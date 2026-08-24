package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	agentctx "github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/scope"
)

// testApp serves an endpoint surface for active-scan tests.
func testApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		q := r.URL.Query().Get("q")
		body := fmt.Sprintf(`{"id":%s,"name":"user","echo":%q,"db":"ERROR: syntax error at or near \"'\" at character 17"}`, strings.TrimPrefix(r.URL.Path, "/api/users/"), q)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})
	mux.HandleFunc("/api/open/1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"id":1,"name":"public"}`)
	})
	return httptest.NewServer(mux)
}

func setupTestDB(t *testing.T) (*core.DB, *core.Project) {
	t.Helper()
	db, err := core.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	proj, err := core.NewProjectStore(db).Create("test-proj")
	if err != nil {
		t.Fatal(err)
	}
	return db, proj
}

// seedRequest inserts a request row for the test server and extracts an endpoint.
func seedRequest(t *testing.T, db *core.DB, proj *core.Project, srv *httptest.Server, method, path string, headers []models.Header, body []byte) {
	t.Helper()
	reqID := core.NewID("req")
	now := core.TimestampNow()
	rawURL := srv.URL + path
	u, _ := url.Parse(rawURL)
	hJSON, _ := json.Marshal(headers)
	port := 80
	if u.Port() != "" {
		fmt.Sscanf(u.Port(), "%d", &port)
	}
	_, err := db.Conn().Exec(`
		INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
			query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
		VALUES (?, ?, 'proxy', ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?)`,
		reqID, proj.ID, method, rawURL, u.Hostname(), port, u.Scheme, u.Path, u.RawQuery,
		string(hJSON), body, "", now,
	)
	if err != nil {
		t.Fatalf("seed request insert: %v", err)
	}
	agentctx.ExtractEndpoint(db.Conn(), proj.ID, reqID, u.Hostname(), method, u.Path, u.RawQuery, nil, body)
	var linked string
	db.Conn().QueryRow(`SELECT endpoint_id FROM requests WHERE id = ?`, reqID).Scan(&linked)
	if linked == "" {
		t.Fatalf("request %s was not linked to an endpoint", reqID)
	}
}

func allowScope(db *core.DB, proj *core.Project) {
	engine, err := scope.NewEngine(db, proj.ID)
	if err != nil {
		panic(err)
	}
	engine.AddRule("include", "127.0.0.1", "host")
}

func TestApplyPosition(t *testing.T) {
	base := &endpointBase{
		Method: "GET",
		URL:    "http://example.com/api/users?q=test",
		Body:   []byte(`{"user":"admin","level":1}`),
	}

	u, body, ok := applyPosition(base, "query.q", "abz99xssmarker")
	if !ok || !strings.Contains(u, "q=abz99xssmarker") {
		t.Errorf("query position failed: %s", u)
	}
	if !ok || len(body) != len(base.Body) {
		t.Errorf("query position should not touch body")
	}

	u, body, ok = applyPosition(base, "body.user", "abz99xssmarker")
	if !ok || !strings.Contains(string(body), `"user":"abz99xssmarker"`) {
		t.Errorf("json body position failed: %s", body)
	}

	base = &endpointBase{Method: "POST", URL: "http://example.com/x", Body: []byte("a=1&b=2")}
	_, body, ok = applyPosition(base, "body.a", "pwn")
	if !ok || string(body) != "a=pwn&b=2" {
		t.Errorf("form body position failed: %s", body)
	}

	if _, _, ok := applyPosition(base, "header.x", "v"); ok {
		t.Error("header position should not be injectable here")
	}
}

func TestRunActive(t *testing.T) {
	srv := testApp()
	defer srv.Close()

	db, proj := setupTestDB(t)
	defer db.Close()

	seedRequest(t, db, proj, srv, "GET", "/api/users/42?q=test", []models.Header{
		{Name: "Authorization", Value: "Bearer token123"},
	}, nil)

	var epID string
	db.Conn().QueryRow(`SELECT id FROM endpoints WHERE project_id = ? LIMIT 1`, proj.ID).Scan(&epID)
	if epID == "" {
		t.Fatal("no endpoint seeded")
	}
	allowScope(db, proj)

	jobID, err := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{"type": "active"})
	if err != nil {
		t.Fatal(err)
	}

	summary, err := RunActive(context.Background(), db, proj, jobID, ActiveOptions{EndpointID: epID, Rate: 100})
	if err != nil {
		t.Fatal(err)
	}
	if summary.NewFindings == 0 {
		t.Fatal("expected findings from active scan")
	}
	if summary.ByCheck["reflected-xss"] == 0 {
		t.Errorf("expected reflected-xss findings, got %v", summary.ByCheck)
	}
	if summary.ByCheck["sqli-error"] == 0 {
		t.Errorf("expected sqli-error findings, got %v", summary.ByCheck)
	}
	if summary.ByCheck["idor-signal"] == 0 {
		t.Errorf("expected idor-signal findings, got %v", summary.ByCheck)
	}

	findings := NewFindingsStore(db, proj.ID)
	list, _ := findings.List("", "active", "", false)
	if len(list) < 2 {
		t.Fatalf("expected >=2 active findings, got %d", len(list))
	}
	for _, f := range list {
		if f.RequestID == "" || f.ResponseID == "" {
			t.Errorf("finding %s missing evidence links", f.ID)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("finding %s missing evidence payload", f.ID)
		}
	}

	// Probe requests must be linked to the scanned endpoint so that later
	// passive scans produce findings with a resolvable endpoint.
	var unlinked int
	db.Conn().QueryRow(`SELECT COUNT(*) FROM requests WHERE source = 'scanner' AND (endpoint_id IS NULL OR endpoint_id = '')`).Scan(&unlinked)
	if unlinked != 0 {
		t.Errorf("expected all scanner probe requests to be linked to an endpoint, %d unlinked", unlinked)
	}
}

func TestRunActiveAuthBypass(t *testing.T) {
	srv := testApp()
	defer srv.Close()

	db, proj := setupTestDB(t)
	defer db.Close()

	seedRequest(t, db, proj, srv, "GET", "/api/open/1", []models.Header{
		{Name: "Authorization", Value: "Bearer token123"},
	}, nil)

	var epID string
	db.Conn().QueryRow(`SELECT id FROM endpoints WHERE project_id = ? LIMIT 1`, proj.ID).Scan(&epID)
	allowScope(db, proj)

	jobID, _ := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{"type": "active"})
	summary, err := RunActive(context.Background(), db, proj, jobID, ActiveOptions{EndpointID: epID, Rate: 100})
	if err != nil {
		t.Fatal(err)
	}
	// /api/open is not a sensitive path → no auth-bypass finding expected.
	if summary.ByCheck["auth-bypass"] != 0 {
		t.Errorf("no auth-bypass expected for non-sensitive path, got %v", summary.ByCheck)
	}
}

func TestNumericPathID(t *testing.T) {
	n, ok := numericPathID("http://example.com/api/users/42?x=1")
	if !ok || n != 42 {
		t.Errorf("numericPathID wrong: %d %v", n, ok)
	}
	if _, ok := numericPathID("http://example.com/api/users/abc"); ok {
		t.Error("non-numeric should not match")
	}
	if _, ok := numericPathID("http://example.com/api/users"); ok {
		t.Error("no numeric segment should not match")
	}
}

func TestSQLErrorDetection(t *testing.T) {
	cases := []string{
		"SQLSTATE[HY000]: General error",
		"psycopg2.errors.UndefinedTable",
		`near "'": syntax error`,
		"ERROR: syntax error at or near",
		"ORA-00933: SQL command not properly ended",
		`"output" : "malformed string: '"`,
		`"output" : "unexpected token: ABZ99XSSMARKER"`,
		`"output" : "Column not found: department"`,
		"org.hsqldb.HsqlException: user lacks privilege or object not found",
	}
	for _, c := range cases {
		if sqliErrorIn([]byte(c)) == "" {
			t.Errorf("should match SQL error: %q", c)
		}
	}
	if sqliErrorIn([]byte("nothing wrong here")) != "" {
		t.Error("clean body should not match")
	}
}

func TestHeaderMap(t *testing.T) {
	base := &endpointBase{Headers: []models.Header{
		{Name: "Authorization", Value: "Bearer x"},
		{Name: "User-Agent", Value: "custom"},
	}}
	m := base.headerMap()
	if m["Authorization"] != "Bearer x" {
		t.Error("Authorization missing")
	}
	if m["User-Agent"] != "custom" {
		t.Error("existing User-Agent should be preserved")
	}
	base = &endpointBase{}
	if m := base.headerMap(); m["User-Agent"] == "" {
		t.Error("default User-Agent should be added")
	}
}
