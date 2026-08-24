package adaptation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
)

type DetectionType string

const (
	RateLimited             DetectionType = "rate_limited"
	IPBlocked               DetectionType = "ip_blocked"
	SessionExpired          DetectionType = "session_expired"
	AuthRequired            DetectionType = "auth_required"
	CaptchaRequired         DetectionType = "captcha_required"
	JSChallenge             DetectionType = "js_challenge"
	WAFBlock                DetectionType = "waf_block"
	SignatureInvalid        DetectionType = "signature_invalid"
	CSRFTokenExpired        DetectionType = "csrf_token_expired"
	TenantMismatch          DetectionType = "tenant_mismatch"
	BusinessLogicStateError DetectionType = "business_logic_state_error"
)

type Detection struct {
	ID         string          `json:"id"`
	ProjectID  string          `json:"project_id"`
	RequestID  string          `json:"request_id,omitempty"`
	ResponseID string          `json:"response_id,omitempty"`
	Type       DetectionType   `json:"type"`
	Confidence string          `json:"confidence"`
	Detail     json.RawMessage `json:"detail"`
	CreatedAt  string          `json:"created_at"`
}

type Adaptation struct {
	ID          string          `json:"id"`
	ProjectID   string          `json:"project_id"`
	DetectionID string          `json:"detection_id,omitempty"`
	Action      string          `json:"action"`
	Status      string          `json:"status"`
	Detail      json.RawMessage `json:"detail"`
	CreatedAt   string          `json:"created_at"`
}

type Engine struct {
	db        *core.DB
	projectID string
}

func NewEngine(db *core.DB, projectID string) *Engine {
	return &Engine{db: db, projectID: projectID}
}

func Classify(status int, headers map[string][]string, body string) (DetectionType, string) {
	lower := strings.ToLower(body)

	if status == 429 {
		return RateLimited, "HTTP 429"
	}
	for _, vals := range headers {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), "retry-after") {
			}
		}
	}
	if strings.Contains(lower, "too many requests") || strings.Contains(lower, "rate limit") {
		return RateLimited, "body contains rate limit message"
	}

	if status == 401 {
		if strings.Contains(lower, "token") && (strings.Contains(lower, "expired") || strings.Contains(lower, "invalid")) {
			return SessionExpired, "401 with token expired"
		}
		return AuthRequired, "HTTP 401"
	}
	if status == 403 {
		if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
			return CSRFTokenExpired, "403 with csrf"
		}
		if strings.Contains(lower, "signature") || strings.Contains(lower, "tamper") {
			return SignatureInvalid, "403 signature invalid"
		}
		if strings.Contains(lower, "waf") || strings.Contains(lower, "blocked") || strings.Contains(lower, "forbidden") {
			return WAFBlock, "403 with WAF block"
		}
		if strings.Contains(lower, "captcha") {
			return CaptchaRequired, "403 captcha"
		}
		return WAFBlock, "HTTP 403 (generic WAF block)"
	}

	if strings.Contains(lower, "challenge passed") || strings.Contains(lower, "welcome") && strings.Contains(lower, "js challenge") {
	} else if strings.Contains(lower, "js challenge") || strings.Contains(lower, "challenge") && strings.Contains(lower, "javascript") {
		return JSChallenge, "challenge page"
	}
	if strings.Contains(lower, "checking your browser") || strings.Contains(lower, "ddos protection") || strings.Contains(lower, "cloudflare") {
		return JSChallenge, "CDN challenge"
	}

	if strings.Contains(lower, "captcha") || strings.Contains(lower, "recaptcha") || strings.Contains(lower, "hcaptcha") {
		return CaptchaRequired, "captcha detected"
	}

	if strings.Contains(lower, "invalid signature") || strings.Contains(lower, "request tampering") {
		return SignatureInvalid, "signature error"
	}

	if status == 406 || status == 419 {
		return WAFBlock, fmt.Sprintf("HTTP %d", status)
	}

	return "", ""
}

func RecommendedAction(dt DetectionType) string {
	switch dt {
	case RateLimited:
		return "slow_down"
	case IPBlocked:
		return "abort_or_switch_proxy"
	case SessionExpired, AuthRequired:
		return "run_auth_macro"
	case CaptchaRequired:
		return "pause_for_human"
	case JSChallenge:
		return "switch_to_browser_session"
	case WAFBlock:
		return "switch_transport_or_backoff"
	case SignatureInvalid:
		return "regenerate_signature_via_js_bridge"
	case CSRFTokenExpired:
		return "refresh_csrf_token"
	case BusinessLogicStateError:
		return "rerun_workflow"
	default:
		return "notify_operator"
	}
}

func (e *Engine) RecordDetection(reqID, respID string, dt DetectionType, confidence string, detail interface{}) (*Detection, error) {
	id := core.NewID("det")
	now := core.TimestampNow()
	detailJSON, _ := json.Marshal(detail)
	if detailJSON == nil {
		detailJSON = []byte(`{}`)
	}
	if confidence == "" {
		confidence = "medium"
	}
	_, err := e.db.Conn().Exec(
		`INSERT INTO detections (id, project_id, request_id, response_id, type, confidence, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, e.projectID, reqID, respID, string(dt), confidence, string(detailJSON), now,
	)
	if err != nil {
		return nil, err
	}
	return &Detection{ID: id, ProjectID: e.projectID, RequestID: reqID, ResponseID: respID, Type: dt, Confidence: confidence, Detail: detailJSON, CreatedAt: now}, nil
}

func (e *Engine) RecordAdaptation(detectionID, action, status string, detail interface{}) (*Adaptation, error) {
	id := core.NewID("adapt")
	now := core.TimestampNow()
	detailJSON, _ := json.Marshal(detail)
	if detailJSON == nil {
		detailJSON = []byte(`{}`)
	}
	_, err := e.db.Conn().Exec(
		`INSERT INTO adaptations (id, project_id, detection_id, action, status, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, e.projectID, detectionID, action, status, string(detailJSON), now,
	)
	if err != nil {
		return nil, err
	}
	return &Adaptation{ID: id, ProjectID: e.projectID, DetectionID: detectionID, Action: action, Status: status, Detail: detailJSON, CreatedAt: now}, nil
}

func (e *Engine) ListDetections(limit int) ([]*Detection, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := e.db.Conn().Query(
		`SELECT id, project_id, COALESCE(request_id,''), COALESCE(response_id,''), type, confidence, detail_json, created_at FROM detections WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, e.projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Detection
	for rows.Next() {
		var d Detection
		var detail string
		if err := rows.Scan(&d.ID, &d.ProjectID, &d.RequestID, &d.ResponseID, &d.Type, &d.Confidence, &detail, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Detail = json.RawMessage(detail)
		out = append(out, &d)
	}
	return out, rows.Err()
}

func (e *Engine) Summary() (map[string]interface{}, error) {
	rows, err := e.db.Conn().Query(`SELECT type, COUNT(*) FROM detections WHERE project_id = ? GROUP BY type`, e.projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var typ string
		var c int
		rows.Scan(&typ, &c)
		counts[typ] = c
	}
	recommendedTransport := "raw-http"
	recommendedPolicy := "default"
	if counts[string(JSChallenge)] > 0 || counts[string(CaptchaRequired)] > 0 {
		recommendedTransport = "browser-session"
	}
	if counts[string(RateLimited)] > 2 {
		recommendedPolicy = "careful_production"
	}
	if counts[string(WAFBlock)] > 5 {
		recommendedTransport = "browser-fetch"
	}
	result := map[string]interface{}{
		"counts":                 counts,
		"rate_limited_events":    counts[string(RateLimited)],
		"waf_blocks":             counts[string(WAFBlock)],
		"session_expired_events": counts[string(SessionExpired)],
		"captcha_events":         counts[string(CaptchaRequired)],
		"js_challenges":          counts[string(JSChallenge)],
		"recommended_transport":  recommendedTransport,
		"recommended_policy":     recommendedPolicy,
	}
	return result, nil
}

func (e *Engine) ScanResponse(reqID, respID string, status int, headers map[string][]string, body string) (*Detection, error) {
	dt, reason := Classify(status, headers, body)
	if dt == "" {
		return nil, nil
	}
	detail := map[string]interface{}{
		"status": status,
		"reason": reason,
		"action": RecommendedAction(dt),
	}
	return e.RecordDetection(reqID, respID, dt, "medium", detail)
}

func (e *Engine) ListAdaptations(limit int) ([]*Adaptation, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := e.db.Conn().Query(
		`SELECT id, project_id, COALESCE(detection_id,''), action, status, detail_json, created_at FROM adaptations WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, e.projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Adaptation
	for rows.Next() {
		var a Adaptation
		var detail string
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.DetectionID, &a.Action, &a.Status, &detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Detail = json.RawMessage(detail)
		out = append(out, &a)
	}
	return out, rows.Err()
}

var _ = sql.ErrNoRows
