// Package scanner implements the passive and active security scanners.
package scanner

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

// FindingsStore persists and queries security findings (signals).
type FindingsStore struct {
	conn      *sql.DB
	projectID string
}

// NewFindingsStore creates a findings store for a project.
func NewFindingsStore(db *core.DB, projectID string) *FindingsStore {
	return &FindingsStore{conn: db.Conn(), projectID: projectID}
}

// Save inserts a finding, deduplicating on (type, check_id, endpoint_id).
// Returns whether the finding was newly created. One finding per endpoint
// and check keeps reports free of duplicates when multiple requests hit
// the same endpoint (crawler re-visits, fuzzer runs, scanner probes).
// Dedup considers both the open and false-positive states: a finding
// re-flagged as a false positive is recreated so retests can surface new
// evidence.
func (s *FindingsStore) Save(sig *models.Signal) (bool, error) {
	sig.ProjectID = s.projectID
	var existing string
	err := s.conn.QueryRow(`
		SELECT id FROM signals
		WHERE project_id = ? AND type = ? AND check_id = ?
		  AND COALESCE(endpoint_id,'') = COALESCE(?, '')
		  AND false_positive = 0
		LIMIT 1`,
		s.projectID, sig.Type, sig.CheckID, sig.EndpointID,
	).Scan(&existing)
	if err == nil {
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}

	evidenceJSON, _ := json.Marshal(sig.Evidence)
	_, err = s.conn.Exec(`
		INSERT INTO signals (id, project_id, type, check_id, title, severity, confidence,
			endpoint_id, request_id, response_id, evidence_json, explanation, remediation,
			false_positive, retested, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)`,
		sig.ID, s.projectID, sig.Type, sig.CheckID, sig.Title, sig.Severity, sig.Confidence,
		nullStr(sig.EndpointID), nullStr(sig.RequestID), nullStr(sig.ResponseID),
		evidenceJSON, sig.Explanation, sig.Remediation, core.TimestampNow(),
	)
	if err != nil {
		return false, err
	}
	return true, nil
}

// List returns findings, newest first, with optional filters.
func (s *FindingsStore) List(severity, sigType, endpointID string, includeFP bool) ([]models.Signal, error) {
	q := `SELECT id, type, check_id, title, severity, confidence,
	             COALESCE(endpoint_id,''), COALESCE(request_id,''), COALESCE(response_id,''),
	             evidence_json, explanation, remediation, false_positive, retested, created_at
	      FROM signals WHERE project_id = ?`
	args := []interface{}{s.projectID}
	if !includeFP {
		q += " AND false_positive = 0"
	}
	if severity != "" {
		sev := strings.Split(severity, ",")
		q += " AND severity IN ("
		for i, sv := range sev {
			if i > 0 {
				q += ","
			}
			q += "?"
			args = append(args, strings.TrimSpace(sv))
		}
		q += ")"
	}
	if sigType != "" {
		q += " AND type = ?"
		args = append(args, sigType)
	}
	if endpointID != "" {
		q += " AND endpoint_id = ?"
		args = append(args, endpointID)
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
	                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC`

	rows, err := s.conn.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Signal
	for rows.Next() {
		var sig models.Signal
		var evJSON string
		var fp, ret int
		if err := rows.Scan(&sig.ID, &sig.Type, &sig.CheckID, &sig.Title, &sig.Severity,
			&sig.Confidence, &sig.EndpointID, &sig.RequestID, &sig.ResponseID, &evJSON,
			&sig.Explanation, &sig.Remediation, &fp, &ret, &sig.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(evJSON), &sig.Evidence)
		sig.FalsePositive = fp == 1
		sig.Retested = ret == 1
		out = append(out, sig)
	}
	return out, rows.Err()
}

// Get returns a single finding.
func (s *FindingsStore) Get(id string) (*models.Signal, error) {
	var sig models.Signal
	var evJSON string
	var fp, ret int
	err := s.conn.QueryRow(`
		SELECT id, type, check_id, title, severity, confidence,
		       COALESCE(endpoint_id,''), COALESCE(request_id,''), COALESCE(response_id,''),
		       evidence_json, explanation, remediation, false_positive, retested, created_at
		FROM signals WHERE id = ? AND project_id = ?`, id, s.projectID,
	).Scan(&sig.ID, &sig.Type, &sig.CheckID, &sig.Title, &sig.Severity, &sig.Confidence,
		&sig.EndpointID, &sig.RequestID, &sig.ResponseID, &evJSON,
		&sig.Explanation, &sig.Remediation, &fp, &ret, &sig.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("finding %q not found", id)
	}
	json.Unmarshal([]byte(evJSON), &sig.Evidence)
	sig.FalsePositive = fp == 1
	sig.Retested = ret == 1
	return &sig, nil
}

// MarkFalsePositive flags a finding as a false positive.
func (s *FindingsStore) MarkFalsePositive(id string) error {
	res, err := s.conn.Exec(`UPDATE signals SET false_positive = 1 WHERE id = ? AND project_id = ?`, id, s.projectID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("finding %q not found", id)
	}
	return nil
}

// UnmarkFalsePositive reopens a finding (for retest workflows).
func (s *FindingsStore) UnmarkFalsePositive(id string) error {
	_, err := s.conn.Exec(`UPDATE signals SET false_positive = 0 WHERE id = ? AND project_id = ?`, id, s.projectID)
	return err
}

// MarkRetested records that a finding was retested.
func (s *FindingsStore) MarkRetested(id string) error {
	_, err := s.conn.Exec(`UPDATE signals SET retested = 1 WHERE id = ? AND project_id = ?`, id, s.projectID)
	return err
}

// Counts returns finding counts broken down by severity.
func (s *FindingsStore) Counts() (map[string]int, error) {
	rows, err := s.conn.Query(
		`SELECT severity, COUNT(*) FROM signals WHERE project_id = ? AND false_positive = 0 GROUP BY severity`,
		s.projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

func nullStr(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}
