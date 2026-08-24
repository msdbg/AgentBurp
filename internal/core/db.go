package core

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
	Path string
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	conn, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1)
	db := &DB{conn: conn, Path: path}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Conn() *sql.DB {
	return db.conn
}
func (db *DB) migrate() error {
	_, err := db.conn.Exec(schema)
	return err
}

const schema = `
-- ─── Projects ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,          -- proj_*
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    scope_json  TEXT NOT NULL DEFAULT '[]',
    active      INTEGER NOT NULL DEFAULT 1
);

-- ─── Requests (immutable once stored) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS requests (
    id             TEXT PRIMARY KEY,       -- req_*
    project_id     TEXT NOT NULL REFERENCES projects(id),
    source         TEXT NOT NULL DEFAULT 'proxy', -- proxy|repeater|fuzzer|crawler|import
    method         TEXT NOT NULL,
    url            TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    scheme         TEXT NOT NULL,
    path           TEXT NOT NULL,
    query_string   TEXT NOT NULL DEFAULT '',
    headers_json   TEXT NOT NULL DEFAULT '[]',
    body_blob      BLOB,
    body_hash      TEXT,
    session_id     TEXT,
    endpoint_id    TEXT,
    created_at     TEXT NOT NULL,
    tags_json      TEXT NOT NULL DEFAULT '[]',
    note           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_requests_project ON requests(project_id);
CREATE INDEX IF NOT EXISTS idx_requests_host    ON requests(host);
CREATE INDEX IF NOT EXISTS idx_requests_method  ON requests(method);
CREATE INDEX IF NOT EXISTS idx_requests_path    ON requests(path);
CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at);

-- ─── Responses (immutable once stored) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS responses (
    id                  TEXT PRIMARY KEY,  -- resp_*
    request_id          TEXT NOT NULL REFERENCES requests(id),
    status_code         INTEGER NOT NULL,
    reason              TEXT NOT NULL DEFAULT '',
    headers_json        TEXT NOT NULL DEFAULT '[]',
    body_blob           BLOB,
    body_hash           TEXT,
    content_type        TEXT NOT NULL DEFAULT '',
    length_bytes        INTEGER NOT NULL DEFAULT 0,
    time_ms             INTEGER NOT NULL DEFAULT 0,
    redirect_chain_json TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_responses_request    ON responses(request_id);
CREATE INDEX IF NOT EXISTS idx_responses_status     ON responses(status_code);

-- ─── Endpoints (normalized, derived from traffic) ──────────────────────────
CREATE TABLE IF NOT EXISTS endpoints (
    id                       TEXT PRIMARY KEY, -- ep_*
    project_id               TEXT NOT NULL REFERENCES projects(id),
    host                     TEXT NOT NULL,
    method                   TEXT NOT NULL,
    path_template            TEXT NOT NULL,    -- /api/users/{id}
    canonical_path           TEXT NOT NULL,    -- /api/users
    first_seen               TEXT NOT NULL,
    last_seen                TEXT NOT NULL,
    auth_required            INTEGER NOT NULL DEFAULT 0,
    request_count            INTEGER NOT NULL DEFAULT 0,
    observed_status_codes    TEXT NOT NULL DEFAULT '[]', -- JSON array
    content_types_json       TEXT NOT NULL DEFAULT '[]',
    UNIQUE(project_id, host, method, path_template)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_project ON endpoints(project_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_host    ON endpoints(host);

-- ─── Parameters (derived from endpoints) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS parameters (
    id                TEXT PRIMARY KEY,  -- param_*
    endpoint_id       TEXT NOT NULL REFERENCES endpoints(id),
    name              TEXT NOT NULL,
    location          TEXT NOT NULL,     -- query|path|header|cookie|json_body|form_body|xml_body|multipart
    inferred_type     TEXT NOT NULL DEFAULT 'string',
    example_values    TEXT NOT NULL DEFAULT '[]', -- JSON array (capped at 5)
    observed_in       TEXT NOT NULL DEFAULT '[]', -- JSON array of req_ids
    UNIQUE(endpoint_id, name, location)
);
CREATE INDEX IF NOT EXISTS idx_parameters_endpoint ON parameters(endpoint_id);

-- ─── Sessions ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,   -- sess_*
    project_id       TEXT NOT NULL REFERENCES projects(id),
    name             TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT '',
    cookies_json     TEXT NOT NULL DEFAULT '[]',
    headers_json     TEXT NOT NULL DEFAULT '[]',
    tokens_json      TEXT NOT NULL DEFAULT '{}',
    auth_profile_id  TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE(project_id, name)
);

-- ─── Jobs (async work: fuzz, crawl, scan, report) ───────────────────────────
CREATE TABLE IF NOT EXISTS jobs (
    id                  TEXT PRIMARY KEY, -- job_*
    project_id          TEXT NOT NULL REFERENCES projects(id),
    type                TEXT NOT NULL,    -- fuzz|crawl|browse|scan|report
    status              TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed|cancelled
    config_json         TEXT NOT NULL DEFAULT '{}',
    result_summary_json TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    started_at          TEXT,
    finished_at         TEXT,
    error               TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status  ON jobs(status);

-- ─── Signals / Findings ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS signals (
    id             TEXT PRIMARY KEY,      -- sig_*
    project_id     TEXT NOT NULL REFERENCES projects(id),
    type           TEXT NOT NULL,         -- passive|active|manual
    check_id       TEXT NOT NULL,         -- e.g. "missing-hsts", "reflected-xss"
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,         -- critical|high|medium|low|info
    confidence     TEXT NOT NULL DEFAULT 'medium', -- high|medium|low
    endpoint_id    TEXT REFERENCES endpoints(id),
    request_id     TEXT REFERENCES requests(id),
    response_id    TEXT REFERENCES responses(id),
    evidence_json  TEXT NOT NULL DEFAULT '{}',
    explanation    TEXT NOT NULL DEFAULT '',
    remediation    TEXT NOT NULL DEFAULT '',
    false_positive INTEGER NOT NULL DEFAULT 0,
    retested       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_project  ON signals(project_id);
CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);
CREATE INDEX IF NOT EXISTS idx_signals_endpoint ON signals(endpoint_id);

-- ─── Events / Audit Log ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,         -- evt_*
    project_id  TEXT,
    timestamp   TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT 'agent', -- agent|proxy|system|user
    action      TEXT NOT NULL,            -- e.g. "request.send", "scope.violation"
    object_type TEXT NOT NULL DEFAULT '',
    object_id   TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT 'ok', -- ok|blocked|error
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_project   ON events(project_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_action    ON events(action);

-- ─── Notes / Annotations ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notes (
    id          TEXT PRIMARY KEY,         -- note_*
    project_id  TEXT NOT NULL REFERENCES projects(id),
    object_type TEXT NOT NULL DEFAULT '', -- request|endpoint|signal|''
    object_id   TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_project ON notes(project_id);
CREATE INDEX IF NOT EXISTS idx_notes_object  ON notes(object_id);

-- ─── Scope Rules ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scope_rules (
    id         TEXT PRIMARY KEY,          -- scope_*
    project_id TEXT NOT NULL REFERENCES projects(id),
    action     TEXT NOT NULL,             -- include|exclude
    pattern    TEXT NOT NULL,             -- host, url pattern, or regex
    pattern_type TEXT NOT NULL DEFAULT 'host', -- host|url|regex
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scope_project ON scope_rules(project_id);

-- ─── Repeater Requests (mutable clones) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS repeater_requests (
    id             TEXT PRIMARY KEY,      -- rreq_*
    project_id     TEXT NOT NULL REFERENCES projects(id),
    parent_req_id  TEXT REFERENCES requests(id),
    method         TEXT NOT NULL,
    url            TEXT NOT NULL,
    headers_json   TEXT NOT NULL DEFAULT '[]',
    body_blob      BLOB,
    session_id     TEXT,
    label          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

-- ─── Fuzz Positions ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fuzz_positions (
    id        TEXT PRIMARY KEY,
    job_id    TEXT NOT NULL REFERENCES jobs(id),
    location  TEXT NOT NULL,   -- query.param|body.field|header.name|cookie.name
    set_index INTEGER NOT NULL DEFAULT 0
);

-- ─── Fuzz Results ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fuzz_results (
    id             TEXT PRIMARY KEY,
    job_id         TEXT NOT NULL REFERENCES jobs(id),
    request_id     TEXT REFERENCES requests(id),
    response_id    TEXT REFERENCES responses(id),
    payload_json   TEXT NOT NULL DEFAULT '[]',
    anomaly        INTEGER NOT NULL DEFAULT 0,
    anomaly_reason TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fuzz_results_job     ON fuzz_results(job_id);
CREATE INDEX IF NOT EXISTS idx_fuzz_results_anomaly ON fuzz_results(anomaly);

-- ─── Transport Profiles (Real-World Hardening: Transport Engine) ──────────────
CREATE TABLE IF NOT EXISTS transport_profiles (
    id          TEXT PRIMARY KEY,            -- trans_*
    project_id  TEXT NOT NULL REFERENCES projects(id),
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,               -- raw-http|fast-http|browser-session|browser-fetch|external-transport
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    UNIQUE(project_id, name)
);
CREATE INDEX IF NOT EXISTS idx_transport_project ON transport_profiles(project_id);

-- ─── Browser Sessions (Real-World Hardening: Browser Session Engine) ─────────
CREATE TABLE IF NOT EXISTS browser_sessions (
    id            TEXT PRIMARY KEY,          -- bses_*
    project_id    TEXT NOT NULL REFERENCES projects(id),
    name          TEXT,
    status        TEXT NOT NULL DEFAULT 'open', -- open|closed|error|waiting_human
    current_url   TEXT,
    profile       TEXT NOT NULL DEFAULT 'stealth', -- stealth|default|headed
    browser_pid   INTEGER,
    created_at    TEXT NOT NULL,
    last_activity TEXT,
    extra_json    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_browser_project ON browser_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_browser_status  ON browser_sessions(status);

-- ─── Auth Macros (Real-World Hardening: Auth Macro Engine) ───────────────────
CREATE TABLE IF NOT EXISTS auth_macros (
    id          TEXT PRIMARY KEY,            -- amac_*
    project_id  TEXT NOT NULL REFERENCES projects(id),
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,               -- simple_login|oauth_authorization_code|oidc_flow|saml_redirect|browser_assisted_login|human_assisted_mfa|token_refresh
    config_yaml TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(project_id, name)
);
CREATE INDEX IF NOT EXISTS idx_authmacro_project ON auth_macros(project_id);

-- ─── Workflows (Real-World Hardening: Workflow / State Engine) ───────────────
CREATE TABLE IF NOT EXISTS workflows (
    id          TEXT PRIMARY KEY,            -- wf_*
    project_id  TEXT NOT NULL REFERENCES projects(id),
    name        TEXT NOT NULL,
    config_yaml TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE(project_id, name)
);
CREATE INDEX IF NOT EXISTS idx_workflow_project ON workflows(project_id);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id          TEXT PRIMARY KEY,            -- wfrun_*
    workflow_id TEXT NOT NULL REFERENCES workflows(id),
    project_id  TEXT NOT NULL REFERENCES projects(id),
    status      TEXT NOT NULL DEFAULT 'running', -- running|done|failed|cancelled
    state_json  TEXT,
    started_at  TEXT,
    finished_at TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_wfrun_workflow ON workflow_runs(workflow_id);
CREATE INDEX IF NOT EXISTS idx_wfrun_project  ON workflow_runs(project_id);

-- ─── Policies (Real-World Hardening: Rate Limiting & Pacing) ─────────────────
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,            -- pol_*
    project_id  TEXT NOT NULL REFERENCES projects(id),
    name        TEXT NOT NULL,
    config_yaml TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE(project_id, name)
);
CREATE INDEX IF NOT EXISTS idx_policy_project ON policies(project_id);

-- ─── Detections & Adaptations (Real-World Hardening: Adaptation Engine) ──────
CREATE TABLE IF NOT EXISTS detections (
    id          TEXT PRIMARY KEY,            -- det_*
    project_id  TEXT NOT NULL REFERENCES projects(id),
    request_id  TEXT REFERENCES requests(id),
    response_id TEXT REFERENCES responses(id),
    type        TEXT NOT NULL,               -- rate_limited|ip_blocked|session_expired|auth_required|captcha_required|js_challenge|waf_block|signature_invalid|csrf_token_expired|tenant_mismatch|business_logic_state_error
    confidence  TEXT NOT NULL DEFAULT 'medium',
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detection_project ON detections(project_id);
CREATE INDEX IF NOT EXISTS idx_detection_type    ON detections(type);

CREATE TABLE IF NOT EXISTS adaptations (
    id           TEXT PRIMARY KEY,           -- adapt_*
    project_id   TEXT NOT NULL REFERENCES projects(id),
    detection_id TEXT REFERENCES detections(id),
    action       TEXT NOT NULL,              -- slow_down|run_auth_macro|switch_transport|pause_for_human|abort|backoff|retry
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|success|failed|skipped
    detail_json  TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_adaptation_project   ON adaptations(project_id);
CREATE INDEX IF NOT EXISTS idx_adaptation_detection ON adaptations(detection_id);

-- ─── Proxy Profiles (Real-World Hardening: Proxy / IP Management) ────────────
CREATE TABLE IF NOT EXISTS proxy_profiles (
    id              TEXT PRIMARY KEY,        -- pprof_*
    project_id      TEXT NOT NULL REFERENCES projects(id),
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,           -- http|https|socks5|upstream|authorized_residential
    url             TEXT NOT NULL,
    auth_json       TEXT,
    rotation_policy TEXT NOT NULL DEFAULT 'disabled', -- disabled|allow_rotation
    created_at      TEXT NOT NULL,
    UNIQUE(project_id, name)
);
CREATE INDEX IF NOT EXISTS idx_proxy_project ON proxy_profiles(project_id);
`
