package report

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/models"
)

type Options struct {
	IncludeFalsePositive bool

	MaxEvidenceBytes int
}

type Project struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type Finding struct {
	models.Signal
	EndpointURL   string `json:"endpoint_url,omitempty"`
	RequestMethod string `json:"request_method,omitempty"`
	RequestURL    string `json:"request_url,omitempty"`
	ResponseCode  int    `json:"response_code,omitempty"`
	ResponseType  string `json:"response_type,omitempty"`
}

type EndpointRow struct {
	ID           string `json:"id"`
	Method       string `json:"method"`
	PathTemplate string `json:"path_template"`
	Host         string `json:"host"`
	RequestCount int    `json:"request_count"`
	LastSeen     string `json:"last_seen"`
}

type NoteRow struct {
	ID         string `json:"id"`
	ObjectID   string `json:"object_id,omitempty"`
	ObjectType string `json:"object_type,omitempty"`
	Content    string `json:"content"`
	CreatedAt  string `json:"created_at"`
}

type ScopeRow struct {
	Action      string `json:"action"`
	Pattern     string `json:"pattern"`
	PatternType string `json:"pattern_type"`
}

type Report struct {
	Project            Project        `json:"project"`
	GeneratedAt        string         `json:"generated_at"`
	Stats              Stats          `json:"stats"`
	Findings           []Finding      `json:"findings"`
	Endpoints          []EndpointRow  `json:"endpoints"`
	Notes              []NoteRow      `json:"notes"`
	Scope              []ScopeRow     `json:"scope"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByCheck    map[string]int `json:"findings_by_check"`

	MaxEvidenceBytes int `json:"-"`
}

type Stats struct {
	Requests  int `json:"requests"`
	Endpoints int `json:"endpoints"`
	Findings  int `json:"findings"`
	Notes     int `json:"notes"`
}

var severityRank = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

var SeverityOrder = []string{"critical", "high", "medium", "low", "info"}

func Load(db *sql.DB, projectID string, opts Options) (*Report, error) {
	r := &Report{
		FindingsBySeverity: map[string]int{},
		FindingsByCheck:    map[string]int{},
	}
	if opts.MaxEvidenceBytes <= 0 {
		opts.MaxEvidenceBytes = 4000
	}
	r.MaxEvidenceBytes = opts.MaxEvidenceBytes
	for _, s := range SeverityOrder {
		r.FindingsBySeverity[s] = 0
	}

	if err := db.QueryRow(
		`SELECT id, name, created_at FROM projects WHERE id = ?`, projectID,
	).Scan(&r.Project.ID, &r.Project.Name, &r.Project.CreatedAt); err != nil {
		return nil, fmt.Errorf("project %q not found", projectID)
	}
	r.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	db.QueryRow(`SELECT COUNT(*) FROM requests WHERE project_id = ?`, projectID).Scan(&r.Stats.Requests)
	db.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE project_id = ?`, projectID).Scan(&r.Stats.Endpoints)
	db.QueryRow(`SELECT COUNT(*) FROM notes WHERE project_id = ?`, projectID).Scan(&r.Stats.Notes)

	fpCond := "false_positive = 0"
	if opts.IncludeFalsePositive {
		fpCond = "1=1"
	}
	db.QueryRow(
		`SELECT COUNT(*) FROM signals WHERE project_id = ? AND `+fpCond, projectID,
	).Scan(&r.Stats.Findings)

	if err := loadFindings(db, projectID, fpCond, r); err != nil {
		return nil, err
	}
	if err := loadEndpoints(db, projectID, r); err != nil {
		return nil, err
	}
	if err := loadNotes(db, projectID, r); err != nil {
		return nil, err
	}
	if err := loadScope(db, projectID, r); err != nil {
		return nil, err
	}
	return r, nil
}

func loadFindings(db *sql.DB, projectID, fpCond string, r *Report) error {
	rows, err := db.Query(`
		SELECT s.id, s.type, s.check_id, s.title, s.severity, s.confidence,
		       COALESCE(s.endpoint_id,''), COALESCE(s.request_id,''), COALESCE(s.response_id,''),
		       s.evidence_json, s.explanation, s.remediation, s.retested, s.created_at,
		       COALESCE(e.method,''), COALESCE(e.path_template,''),
		       COALESCE(req.method,''), COALESCE(req.url,''),
		       COALESCE(resp.status_code,0), COALESCE(resp.content_type,'')
		FROM signals s
		LEFT JOIN endpoints e ON e.id = s.endpoint_id
		LEFT JOIN requests req ON req.id = s.request_id
		LEFT JOIN responses resp ON resp.id = s.response_id
		WHERE s.project_id = ? AND `+fpCond+`
		ORDER BY
			CASE s.severity
				WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
				WHEN 'low' THEN 3 ELSE 4
			END,
			s.created_at DESC`,
		projectID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var f Finding
		var evJSON, epMethod, epPath, reqMethod, reqURL, respType string
		var respCode, retested int
		if err := rows.Scan(
			&f.ID, &f.Type, &f.CheckID, &f.Title, &f.Severity, &f.Confidence,
			&f.EndpointID, &f.RequestID, &f.ResponseID, &evJSON,
			&f.Explanation, &f.Remediation, &retested, &f.CreatedAt,
			&epMethod, &epPath, &reqMethod, &reqURL,
			&respCode, &respType,
		); err != nil {
			return err
		}
		f.Evidence = map[string]interface{}{}
		json.Unmarshal([]byte(evJSON), &f.Evidence)
		f.EndpointURL = strings.TrimSpace(epMethod + " " + epPath)
		f.RequestMethod = reqMethod
		f.RequestURL = reqURL
		f.ResponseCode = respCode
		f.ResponseType = respType
		f.Retested = retested == 1
		r.Findings = append(r.Findings, f)
		r.FindingsBySeverity[f.Severity]++
		r.FindingsByCheck[f.CheckID]++
	}
	return rows.Err()
}

func loadEndpoints(db *sql.DB, projectID string, r *Report) error {
	rows, err := db.Query(`
		SELECT id, method, path_template, host, request_count, COALESCE(last_seen,'')
		FROM endpoints WHERE project_id = ?
		ORDER BY request_count DESC, path_template ASC`, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e EndpointRow
		if err := rows.Scan(&e.ID, &e.Method, &e.PathTemplate, &e.Host, &e.RequestCount, &e.LastSeen); err != nil {
			return err
		}
		r.Endpoints = append(r.Endpoints, e)
	}
	return rows.Err()
}

func loadNotes(db *sql.DB, projectID string, r *Report) error {
	rows, err := db.Query(`
		SELECT id, object_type, object_id, content, created_at
		FROM notes WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n NoteRow
		if err := rows.Scan(&n.ID, &n.ObjectType, &n.ObjectID, &n.Content, &n.CreatedAt); err != nil {
			return err
		}
		r.Notes = append(r.Notes, n)
	}
	return rows.Err()
}

func loadScope(db *sql.DB, projectID string, r *Report) error {
	rows, err := db.Query(`
		SELECT action, pattern, pattern_type FROM scope_rules
		WHERE project_id = ? ORDER BY action ASC, pattern ASC`, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s ScopeRow
		if err := rows.Scan(&s.Action, &s.Pattern, &s.PatternType); err != nil {
			return err
		}
		r.Scope = append(r.Scope, s)
	}
	return rows.Err()
}

func (r *Report) EvidenceText(f Finding) string {
	raw, err := json.MarshalIndent(f.Evidence, "", "  ")
	if err != nil {
		return "(unparseable evidence)"
	}
	if len(raw) > r.MaxEvidenceBytes {
		raw = append(raw[:r.MaxEvidenceBytes], []byte("\n… (truncated)")...)
	}
	return string(raw)
}

func (r *Report) SortedSeverities() []string {
	keys := make([]string, 0, len(r.FindingsBySeverity))
	for k, v := range r.FindingsBySeverity {
		if v > 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return severityRank[keys[i]] < severityRank[keys[j]]
	})
	return keys
}

func (r *Report) CheckLabels() []string {
	keys := make([]string, 0, len(r.FindingsByCheck))
	for k := range r.FindingsByCheck {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *Finding) HTTPMethod() string {
	m := strings.ToUpper(f.RequestMethod)
	if m == "" {
		return "GET"
	}
	return m
}
