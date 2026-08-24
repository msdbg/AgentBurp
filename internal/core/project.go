package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func DefaultProjectsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentburp", "projects")
}

func ProjectDir(name string) string {
	return filepath.Join(DefaultProjectsDir(), name)
}

func ProjectDBPath(name string) string {
	return filepath.Join(ProjectDir(name), "agentburp.db")
}

type Project struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	CreatedAt string          `json:"created_at"`
	Config    json.RawMessage `json:"config"`
}

type ProjectStore struct {
	db *sql.DB
}

func NewProjectStore(db *DB) *ProjectStore {
	return &ProjectStore{db: db.Conn()}
}

func (s *ProjectStore) Create(name string) (*Project, error) {
	id := NewID("proj")
	now := TimestampNow()
	_, err := s.db.Exec(
		`INSERT INTO projects (id, name, created_at, config_json, scope_json) VALUES (?, ?, ?, '{}', '[]')`,
		id, name, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create project %q: %w", name, err)
	}
	return &Project{ID: id, Name: name, CreatedAt: now}, nil
}

func (s *ProjectStore) Get(idOrName string) (*Project, error) {
	row := s.db.QueryRow(
		`SELECT id, name, created_at, config_json FROM projects WHERE id = ? OR name = ? LIMIT 1`,
		idOrName, idOrName,
	)
	var p Project
	var configJSON string
	if err := row.Scan(&p.ID, &p.Name, &p.CreatedAt, &configJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("project %q not found", idOrName)
		}
		return nil, err
	}
	p.Config = json.RawMessage(configJSON)
	return &p, nil
}

func (s *ProjectStore) List() ([]*Project, error) {
	rows, err := s.db.Query(
		`SELECT id, name, created_at, config_json FROM projects WHERE active = 1 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		var p Project
		var configJSON string
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &configJSON); err != nil {
			return nil, err
		}
		p.Config = json.RawMessage(configJSON)
		projects = append(projects, &p)
	}
	return projects, rows.Err()
}

func (s *ProjectStore) Delete(idOrName string) error {
	res, err := s.db.Exec(
		`UPDATE projects SET active = 0 WHERE id = ? OR name = ?`,
		idOrName, idOrName,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("project %q not found", idOrName)
	}
	return nil
}
