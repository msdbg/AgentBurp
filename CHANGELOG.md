# Changelog

All notable changes to AgentBurp will be documented in this file.

## v1.0.0 — 2026-08-24

Initial public release. Agent-first, CLI-native web application security testing toolkit.

### Features
- **Proxy**: HTTP/HTTPS interception via `go-mitmproxy` with automatic TLS, scope enforcement, capture
- **History**: Full request/response archive with filtering, search, export (JSON/HAR/CSV)
- **Endpoint Map**: Auto-normalized endpoint + parameter inventory
- **Repeater**: Clone, edit, replay captured requests with session/transport control
- **Fuzzer**: Intruder-style engine — sniper, battering ram, pitchfork, cluster bomb
- **Crawler**: BFS link/JS/form discovery with optional headless Chrome (`go-rod` + stealth)
- **Scanner**: 14 passive checks (headers, cookies, CORS, disclosure, etc.) + 8 active probes (XSS, SQLi, IDOR, JWT `alg:none`, path traversal, auth bypass)
- **Findings**: Severity/confidence/evidence, false-positive tracking, one-click retest
- **Sequencer**: Token randomness analysis (entropy, charset, sequential detection)
- **Auth**: Login profiles, cookie jars, session capture, auth macros (SSO/OAuth/MFA)
- **Import**: OpenAPI 3.x / Swagger 2.0 / Postman collections
- **Reports**: Markdown, HTML, JSON, SARIF 2.1.0
- **Browser**: Real Chrome via `go-rod` for JS challenges, WAF bypass, cookie export
- **Transport**: Pluggable backends — raw, fast, browser-session, browser-fetch, external
- **Workflow**: YAML state machine for business logic testing
- **Policy**: Rate limiting, backoff, jitter policies
- **Ops**: Jobs, audit logs, notes, project dashboard

### Data
- SQLite WAL mode at `~/.agentburp/projects/<name>/agentburp.db` (18 tables, pure-Go via `modernc.org/sqlite` — no CGO)

### CLI
- Every command supports `--json` (machine-readable) and `--dry-run` (safe preview)
- Stable prefixed IDs: `req_`, `ep_`, `sig_`, `sess_`, `job_`, etc.
- Single binary, no runtime dependencies

### Build
- Go 1.26, `make build` / `make build-all` (windows/linux/darwin amd64+arm64)
- Verified: `go vet` clean, `go test ./...` passing (9 packages), `gofmt` clean
