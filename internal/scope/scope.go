// Package scope implements AgentBurp's scope and safety enforcement engine.
// The scope engine is BLOCKING, not advisory. Out-of-scope requests are
// rejected at every layer: proxy, repeater, fuzzer, and crawler.
package scope

import (
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

// Engine enforces scope rules for a project.
type Engine struct {
	db         *sql.DB
	projectID  string
	rules      []models.ScopeRule
	regexCache map[string]*regexp.Regexp // compiled regex patterns, keyed by rule ID
}

// NewEngine creates a scope engine and loads rules from the database.
func NewEngine(db *core.DB, projectID string) (*Engine, error) {
	e := &Engine{db: db.Conn(), projectID: projectID}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload refreshes scope rules from the database.
func (e *Engine) Reload() error {
	rows, err := e.db.Query(
		`SELECT id, project_id, action, pattern, pattern_type, created_at
		 FROM scope_rules WHERE project_id = ? ORDER BY created_at`,
		e.projectID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []models.ScopeRule
	for rows.Next() {
		var r models.ScopeRule
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Action, &r.Pattern, &r.PatternType, &r.CreatedAt); err != nil {
			return err
		}
		rules = append(rules, r)
	}
	e.rules = rules

	// Pre-compile regex patterns so matchRule doesn't recompile on every request.
	e.regexCache = make(map[string]*regexp.Regexp, len(rules))
	for _, r := range rules {
		if r.PatternType == "regex" {
			if re, err := regexp.Compile(r.Pattern); err == nil {
				e.regexCache[r.ID] = re
			}
		}
	}

	return rows.Err()
}

// CheckResult is the result of a scope check.
type CheckResult struct {
	InScope bool   `json:"in_scope"`
	Reason  string `json:"reason"`
	Rule    string `json:"matched_rule,omitempty"`
}

// Check returns whether the given URL is in scope.
// If no rules are defined, everything is considered in scope
// (permissive default — the agent must explicitly narrow scope).
func (e *Engine) Check(rawURL string) CheckResult {
	if len(e.rules) == 0 {
		return CheckResult{InScope: true, Reason: "no scope rules defined — all traffic in scope"}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return CheckResult{InScope: false, Reason: fmt.Sprintf("invalid url: %v", err)}
	}

	host := parsed.Hostname()

	// Rules are evaluated in order. LAST matching rule wins.
	// This mirrors Burp's scope behavior.
	result := CheckResult{InScope: false, Reason: "no matching include rule"}

	for _, rule := range e.rules {
		matched := e.matchRule(rule, host, rawURL)
		if matched {
			if rule.Action == "include" {
				result = CheckResult{InScope: true, Reason: "matched include rule", Rule: rule.ID}
			} else {
				result = CheckResult{InScope: false, Reason: "matched exclude rule", Rule: rule.ID}
			}
		}
	}
	return result
}

// IsInScope is a convenience wrapper that returns a bool.
func (e *Engine) IsInScope(rawURL string) bool {
	return e.Check(rawURL).InScope
}

// AddRule adds a scope rule to the database and reloads.
func (e *Engine) AddRule(action, pattern, patternType string) (*models.ScopeRule, error) {
	if action != "include" && action != "exclude" {
		return nil, fmt.Errorf("action must be 'include' or 'exclude'")
	}
	if patternType != "host" && patternType != "url" && patternType != "regex" {
		return nil, fmt.Errorf("pattern_type must be host|url|regex")
	}
	// Validate regex if type is regex
	if patternType == "regex" {
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
	}

	id := core.NewID("scope")
	now := core.TimestampNow()
	_, err := e.db.Exec(
		`INSERT INTO scope_rules (id, project_id, action, pattern, pattern_type, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, e.projectID, action, pattern, patternType, now,
	)
	if err != nil {
		return nil, err
	}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return &models.ScopeRule{
		ID: id, ProjectID: e.projectID, Action: action,
		Pattern: pattern, PatternType: patternType, CreatedAt: now,
	}, nil
}

// RemoveRule deletes a scope rule by ID.
func (e *Engine) RemoveRule(ruleID string) error {
	_, err := e.db.Exec(`DELETE FROM scope_rules WHERE id = ? AND project_id = ?`, ruleID, e.projectID)
	if err != nil {
		return err
	}
	return e.Reload()
}

// ListRules returns all scope rules for the project.
func (e *Engine) ListRules() []models.ScopeRule {
	return e.rules
}

// matchRule returns true if the given host/url matches the rule pattern.
func (e *Engine) matchRule(rule models.ScopeRule, host, rawURL string) bool {
	switch rule.PatternType {
	case "host":
		pattern := rule.Pattern
		// Support wildcard prefix: *.example.com
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // .example.com
			return strings.HasSuffix(host, suffix) || host == pattern[2:]
		}
		return strings.EqualFold(host, pattern)

	case "url":
		return strings.HasPrefix(rawURL, rule.Pattern)

	case "regex":
		if re, ok := e.regexCache[rule.ID]; ok {
			return re.MatchString(rawURL)
		}
		return false
	}
	return false
}
