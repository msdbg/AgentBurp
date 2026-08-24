package importer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	agentctx "github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

func ImportIntoDB(db *core.DB, proj *core.Project, plan *Plan) (*models.ImportSummary, error) {
	summary := &models.ImportSummary{
		Source:   plan.Source,
		Format:   plan.Format,
		Methods:  map[string]int{},
		Warnings: plan.Warnings,
	}

	conn := db.Conn()
	now := core.TimestampNow()
	for _, spec := range plan.Requests {
		u, err := url.Parse(spec.URL)
		if err != nil || u.Host == "" {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("skip %s %s (unparsable URL)", spec.Method, spec.URL))
			continue
		}

		reqID := core.NewID("req")
		var headers []models.Header
		for _, h := range spec.Headers {
			name, v, _ := strings.Cut(h, ":")
			if strings.TrimSpace(name) == "" {
				continue
			}
			headers = append(headers, models.Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(v)})
		}
		headersJSON, _ := json.Marshal(headers)

		path := u.Path
		if path == "" {
			path = "/"
		}
		port := 80
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &port)
		} else if u.Scheme == "https" {
			port = 443
		}

		_, err = conn.Exec(`
			INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
				query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
			VALUES (?, ?, 'import', ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?)`,
			reqID, proj.ID, strings.ToUpper(spec.Method), spec.URL, u.Hostname(), port, u.Scheme, path,
			u.RawQuery, string(headersJSON), spec.Body, spec.Source, now,
		)
		if err != nil {
			return nil, fmt.Errorf("insert imported request: %w", err)
		}

		summary.RequestsCreated++
		summary.Methods[strings.ToUpper(spec.Method)]++

		hdr := http.Header{}
		for _, h := range headers {
			hdr.Set(h.Name, h.Value)
		}
		agentctx.ExtractEndpoint(conn, proj.ID, reqID, u.Hostname(), strings.ToUpper(spec.Method), path, u.RawQuery, hdr, spec.Body)
	}

	conn.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE project_id = ?`, proj.ID).Scan(&summary.Endpoints)
	return summary, nil
}
