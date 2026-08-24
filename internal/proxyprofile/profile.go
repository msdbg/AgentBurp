package proxyprofile

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
)

type Store struct {
	db        *core.DB
	projectID string
}

func NewStore(db *core.DB, projectID string) *Store {
	return &Store{db: db, projectID: projectID}
}

func (s *Store) Create(name, typ, rawURL, rotation string) (string, error) {
	if name == "" || typ == "" || rawURL == "" {
		return "", fmt.Errorf("--name, --type, and --url are required")
	}
	valid := map[string]bool{"http": true, "https": true, "socks5": true, "upstream": true, "authorized_residential": true}
	if !valid[typ] {
		return "", fmt.Errorf("invalid proxy type %q — valid: http, https, socks5, upstream, authorized_residential", typ)
	}
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return "", fmt.Errorf("invalid proxy url %q: %w", rawURL, err)
	}
	if rotation == "" {
		rotation = "disabled"
	}
	if rotation != "disabled" && rotation != "allow_rotation" {
		return "", fmt.Errorf("rotation_policy must be disabled or allow_rotation")
	}
	id := core.NewID("pprof")
	now := core.TimestampNow()
	_, err := s.db.Conn().Exec(
		`INSERT INTO proxy_profiles (id, project_id, name, type, url, rotation_policy, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, s.projectID, name, typ, rawURL, rotation, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("proxy profile %q already exists", name)
		}
		return "", err
	}
	return id, nil
}

func (s *Store) Get(identifier string) (map[string]string, error) {
	var id, name, typ, rawURL, rotation, createdAt string
	var authJSON *string
	err := s.db.Conn().QueryRow(
		`SELECT id, name, type, url, COALESCE(auth_json,''), rotation_policy, created_at FROM proxy_profiles WHERE (id = ? OR name = ?) AND project_id = ?`,
		identifier, identifier, s.projectID,
	).Scan(&id, &name, &typ, &rawURL, &authJSON, &rotation, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("proxy profile %q not found", identifier)
	}
	return map[string]string{"id": id, "name": name, "type": typ, "url": rawURL, "rotation_policy": rotation, "created_at": createdAt}, nil
}

func (s *Store) List() ([]map[string]string, error) {
	rows, err := s.db.Conn().Query(`SELECT id, name, type, url, rotation_policy, created_at FROM proxy_profiles WHERE project_id = ? ORDER BY created_at`, s.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, name, typ, rawURL, rotation, createdAt string
		rows.Scan(&id, &name, &typ, &rawURL, &rotation, &createdAt)
		out = append(out, map[string]string{"id": id, "name": name, "type": typ, "url": rawURL, "rotation_policy": rotation, "created_at": createdAt})
	}
	return out, rows.Err()
}

func (s *Store) Delete(identifier string) error {
	res, err := s.db.Conn().Exec(`DELETE FROM proxy_profiles WHERE (id = ? OR name = ?) AND project_id = ?`, identifier, identifier, s.projectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("proxy profile %q not found", identifier)
	}
	return nil
}

func (s *Store) Check(identifier string) (map[string]interface{}, error) {
	p, err := s.Get(identifier)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(p["url"])
	return map[string]interface{}{
		"id":              p["id"],
		"name":            p["name"],
		"type":            p["type"],
		"url":             p["url"],
		"host":            u.Host,
		"rotation_policy": p["rotation_policy"],
		"status":          "configured",
		"note":            "Proxy profile is configured. Use --allow-rotation only if engagement explicitly authorizes rotation.",
	}, nil
}
