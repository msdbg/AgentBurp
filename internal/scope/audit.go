// Package scope — audit log writer.
package scope

import (
	"database/sql"
	"encoding/json"

	"github.com/msdbg/AgentBurp/internal/core"
)

// AuditLogger writes immutable event records to the events table.
type AuditLogger struct {
	db        *sql.DB
	projectID string
}

// NewAuditLogger creates an audit logger for the given project.
func NewAuditLogger(db *core.DB, projectID string) *AuditLogger {
	return &AuditLogger{db: db.Conn(), projectID: projectID}
}

// Log writes a new event to the audit log.
func (l *AuditLogger) Log(actor, action, objectType, objectID, result string, detail map[string]interface{}) {
	id := core.NewID("evt")
	now := core.TimestampNow()
	detailJSON := "{}"
	if detail != nil {
		b, _ := json.Marshal(detail)
		detailJSON = string(b)
	}
	// Best-effort — never block on audit log failures.
	l.db.Exec( //nolint:errcheck
		`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, l.projectID, now, actor, action, objectType, objectID, result, detailJSON,
	)
}

// LogScopeViolation is a convenience method for scope violations.
func (l *AuditLogger) LogScopeViolation(url, reason string) {
	l.Log("agent", "scope.violation", "url", url, "blocked", map[string]interface{}{
		"url":    url,
		"reason": reason,
	})
}

// LogRequestSent logs a successful request dispatch.
func (l *AuditLogger) LogRequestSent(reqID, source string) {
	l.Log("agent", "request.send", "request", reqID, "ok", map[string]interface{}{
		"source": source,
	})
}
