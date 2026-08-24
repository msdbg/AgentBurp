package core

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/msdbg/AgentBurp/internal/models"
)

type JobStore struct {
	db *DB
}

func NewJobStore(db *DB) *JobStore {
	return &JobStore{db: db}
}

func (s *JobStore) Create(projectID, jobType string, config map[string]interface{}) (string, error) {
	id := NewID("job")
	now := TimestampNow()
	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("marshal job config: %w", err)
	}
	_, err = s.db.Conn().Exec(`
		INSERT INTO jobs (id, project_id, type, status, config_json, created_at)
		VALUES (?, ?, ?, 'queued', ?, ?)`,
		id, projectID, jobType, string(configJSON), now,
	)
	if err != nil {
		return "", fmt.Errorf("create job: %w", err)
	}
	return id, nil
}

func (s *JobStore) Get(jobID string) (*models.Job, error) {
	var j models.Job
	var configJSON, summaryJSON, startedAt, finishedAt sql.NullString
	err := s.db.Conn().QueryRow(`
		SELECT id, project_id, type, status, config_json, result_summary_json,
		       created_at, started_at, finished_at, COALESCE(error,'')
		FROM jobs WHERE id = ?`, jobID,
	).Scan(&j.ID, &j.ProjectID, &j.Type, &j.Status, &configJSON, &summaryJSON,
		&j.CreatedAt, &startedAt, &finishedAt, &j.Error)
	if err != nil {
		return nil, fmt.Errorf("job %q not found", jobID)
	}
	if configJSON.Valid && configJSON.String != "" {
		json.Unmarshal([]byte(configJSON.String), &j.Config)
	}
	if summaryJSON.Valid && summaryJSON.String != "" {
		json.Unmarshal([]byte(summaryJSON.String), &j.ResultSummary)
	}
	if startedAt.Valid {
		j.StartedAt = startedAt.String
	}
	if finishedAt.Valid {
		j.FinishedAt = finishedAt.String
	}
	return &j, nil
}

func (s *JobStore) GetConfig(jobID string) (map[string]interface{}, error) {
	j, err := s.Get(jobID)
	if err != nil {
		return nil, err
	}
	return j.Config, nil
}

func (s *JobStore) SetConfig(jobID string, config map[string]interface{}) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal job config: %w", err)
	}
	_, err = s.db.Conn().Exec(`UPDATE jobs SET config_json = ? WHERE id = ?`, string(configJSON), jobID)
	return err
}

func (s *JobStore) SetStatus(jobID, status string) error {
	_, err := s.db.Conn().Exec(`UPDATE jobs SET status = ? WHERE id = ?`, status, jobID)
	return err
}

func (s *JobStore) MarkRunning(jobID string) error {
	_, err := s.db.Conn().Exec(`
		UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?`,
		TimestampNow(), jobID,
	)
	return err
}

func (s *JobStore) MarkDone(jobID string, summary map[string]interface{}) error {
	summaryJSON, _ := json.Marshal(summary)
	_, err := s.db.Conn().Exec(`
		UPDATE jobs SET status = 'done', result_summary_json = ?, finished_at = ? WHERE id = ?`,
		string(summaryJSON), TimestampNow(), jobID,
	)
	return err
}

func (s *JobStore) MarkFailed(jobID string, errMsg string) error {
	_, err := s.db.Conn().Exec(`
		UPDATE jobs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?`,
		errMsg, TimestampNow(), jobID,
	)
	return err
}

func (s *JobStore) Cancel(jobID string) error {
	_, err := s.db.Conn().Exec(`
		UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE id = ?`,
		TimestampNow(), jobID,
	)
	return err
}

func (s *JobStore) IsCancelled(jobID string) bool {
	var status string
	err := s.db.Conn().QueryRow(`SELECT status FROM jobs WHERE id = ?`, jobID).Scan(&status)
	return err == nil && status == "cancelled"
}

func (s *JobStore) List(projectID, statusFilter string) ([]models.Job, error) {
	q := `SELECT id, project_id, type, status, config_json, result_summary_json,
	             created_at, COALESCE(started_at,''), COALESCE(finished_at,''), COALESCE(error,'')
	      FROM jobs WHERE project_id = ?`
	args := []interface{}{projectID}
	if statusFilter != "" {
		q += ` AND status = ?`
		args = append(args, statusFilter)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := s.db.Conn().Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []models.Job
	for rows.Next() {
		var j models.Job
		var configJSON, summaryJSON string
		if err := rows.Scan(&j.ID, &j.ProjectID, &j.Type, &j.Status, &configJSON, &summaryJSON,
			&j.CreatedAt, &j.StartedAt, &j.FinishedAt, &j.Error); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(configJSON), &j.Config)
		json.Unmarshal([]byte(summaryJSON), &j.ResultSummary)
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}
