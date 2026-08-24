package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/msdbg/AgentBurp/internal/core"
)

func seedReportDB(t *testing.T) (*core.DB, string) {
	t.Helper()
	db, err := core.Open(t.TempDir() + "/report.db")
	if err != nil {
		t.Fatal(err)
	}
	proj, err := core.NewProjectStore(db).Create("report-proj")
	if err != nil {
		t.Fatal(err)
	}
	now := core.TimestampNow()

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Conn().Exec(q, args...); err != nil {
			t.Fatalf("seed exec failed: %v\nquery: %s", err, q)
		}
	}

	exec(`
		INSERT INTO endpoints (id, project_id, host, method, path_template, canonical_path,
			first_seen, last_seen, auth_required, request_count, observed_status_codes, content_types_json)
		VALUES ('ep_1', ?, 'api.test', 'GET', '/api/users/{id}', '/api/users', ?, ?, 1, 3, '[200,404]', '["application/json"]')`,
		proj.ID, now, now)

	reqID := core.NewID("req")
	respID := core.NewID("resp")
	exec(`
		INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
			query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
		VALUES (?, ?, 'proxy', 'GET', 'http://api.test/api/users/1', 'api.test', 80, 'http', '/api/users/1',
			'id=1', '[]', NULL, '', '', '', ?)`, reqID, proj.ID, now)
	exec(`
		INSERT INTO responses (id, request_id, status_code, reason, headers_json, body_blob,
			body_hash, content_type, length_bytes, time_ms, created_at)
		VALUES (?, ?, 200, '', '[{"name":"Content-Type","value":"application/json"}]',
			'{"id":1,"name":"admin"}', '', 'application/json', 24, 3, ?)`,
		respID, reqID, now)

	exec(`
		INSERT INTO signals (id, project_id, type, check_id, title, severity, confidence,
			endpoint_id, request_id, response_id, evidence_json, explanation, remediation,
			false_positive, retested, created_at)
		VALUES ('sig_1', ?, 'active', 'reflected-xss', 'Reflected XSS', 'high', 'high',
			'ep_1', ?, ?, '{"payload":"<script>alert(1)</script>","position":"query"}',
			'Input reflected unsanitized.', 'Encode output.', 0, 1, ?)`,
		proj.ID, reqID, respID, now)
	exec(`
		INSERT INTO signals (id, project_id, type, check_id, title, severity, confidence,
			endpoint_id, evidence_json, explanation, false_positive, created_at)
		VALUES ('sig_2', ?, 'passive', 'missing-security-headers', 'Missing security headers', 'low', 'medium',
			'ep_1', '{}', 'No CSP header.', 1, ?)`,
		proj.ID, now)

	exec(`
		INSERT INTO notes (id, project_id, object_type, object_id, content, created_at)
		VALUES ('note_1', ?, 'signal', 'sig_1', 'Verify on staging before release.', ?)`,
		proj.ID, now)
	exec(`
		INSERT INTO scope_rules (id, project_id, action, pattern, pattern_type, created_at)
		VALUES ('scope_1', ?, 'include', 'api.test', 'host', ?)`,
		proj.ID, now)

	return db, proj.ID
}

func TestLoad(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()

	r, err := Load(db.Conn(), projID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Project.Name != "report-proj" {
		t.Errorf("project name: got %q", r.Project.Name)
	}
	if r.Stats.Requests != 1 || r.Stats.Endpoints != 1 || r.Stats.Notes != 1 {
		t.Errorf("stats wrong: %+v", r.Stats)
	}
	// sig_2 is a false positive → excluded by default
	if r.Stats.Findings != 1 {
		t.Errorf("expected 1 non-FP finding, got %d", r.Stats.Findings)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "sig_1" {
		t.Fatalf("findings wrong: %+v", r.Findings)
	}
	f := r.Findings[0]
	if f.EndpointURL != "GET /api/users/{id}" {
		t.Errorf("endpoint url: got %q", f.EndpointURL)
	}
	if f.ResponseCode != 200 || f.RequestURL == "" {
		t.Errorf("request/response context missing: %+v", f)
	}
	if f.Evidence["payload"] != "<script>alert(1)</script>" {
		t.Errorf("evidence not decoded: %+v", f.Evidence)
	}
	if r.FindingsBySeverity["high"] != 1 {
		t.Errorf("severity breakdown wrong: %+v", r.FindingsBySeverity)
	}
	if r.FindingsByCheck["reflected-xss"] != 1 {
		t.Errorf("check breakdown wrong: %+v", r.FindingsByCheck)
	}
	if len(r.Scope) != 1 || r.Scope[0].Pattern != "api.test" {
		t.Errorf("scope wrong: %+v", r.Scope)
	}
}

func TestLoadIncludeFP(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()

	r, err := Load(db.Conn(), projID, Options{IncludeFalsePositive: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Stats.Findings != 2 {
		t.Errorf("expected 2 findings with FP included, got %d", r.Stats.Findings)
	}
}

func TestMarkdown(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()
	r, err := Load(db.Conn(), projID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Markdown()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"# Security Assessment Report - report-proj",
		"| Requests captured | 1 |",
		"## Findings",
		"### 1. Reflected XSS",
		"**Severity:** high",
		"GET /api/users/{id}",
		"## Endpoints (1)",
		"## Notes (1)",
		"## Scope",
		"include",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("markdown missing %q", want)
		}
	}

	if strings.Contains(s, "sig_2") || strings.Contains(s, "Missing security headers") {
		t.Error("false positive leaked into markdown report")
	}
}

func TestHTML(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()
	r, err := Load(db.Conn(), projID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Security Assessment Report — report-proj",
		"sev-high",
		"Reflected XSS",
		"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("html missing %q", want)
		}
	}

	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Error("html template did not escape payload")
	}
}

func TestJSON(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()
	r, err := Load(db.Conn(), projID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["project"].(map[string]interface{})["name"] != "report-proj" {
		t.Error("json project name wrong")
	}
}

func TestSARIF(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()
	r, err := Load(db.Conn(), projID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("sarif version: got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "AgentBurp" {
		t.Errorf("driver: got %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	res := run.Results[0]
	if res.RuleID != "reflected-xss" || res.Level != "error" {
		t.Errorf("result wrong: %+v", res)
	}
	if res.PartialFingerprints["agentburpFindingID"] != "sig_1" {
		t.Errorf("fingerprint missing: %+v", res.PartialFingerprints)
	}
	if len(res.Locations) != 1 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
		t.Error("result location missing")
	}
}

func TestEvidenceTruncation(t *testing.T) {
	db, projID := seedReportDB(t)
	defer db.Close()
	r, err := Load(db.Conn(), projID, Options{MaxEvidenceBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	text := r.EvidenceText(r.Findings[0])
	if !strings.Contains(text, "truncated") {
		t.Error("expected truncation marker")
	}
}
