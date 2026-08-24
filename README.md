<p align="center">
  <img src="agentburp.png" alt="Centered Image">
</p>
<p align="center">
  <h1 align="center">AgentBurp</h1>
  <p align="center">
    <strong>Agent-first web application security testing tool</strong>
  </p>
  <p align="center">
    A CLI-native toolkit designed for AI agents (and humans, ofcourse).
    <br />
    Every command supports structured JSON and<code>--dry-run</code>.
  </p>
  <p align="center">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
    <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white" alt="Go 1.22+"></a>
    <a href="https://github.com/msdbg/AgentBurp/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build"></a>
    <a href="https://github.com/msdbg/AgentBurp/releases"><img src="https://img.shields.io/badge/release-v1.0.0-orange" alt="Release"></a>
  </p>
</p>

---

## What's Corny AgentBurp ?
the primary user is an AI agent giving CLI commands and consuming structured JSON, it operates on it's own and gives findings to humans for review. try it, just give the Compiled Go binary to your agent living in your terminal, the results depend on your system prompt and LLM model you are using to test.

- **Native AI autonomy**: every command returns JSON, no translation layers needed
- **Single binary**: compiled Go, no JVM, no runtime dependencies, runs anywhere
- **Open data**: SQLite database, query it directly with SQL
- **Safety-first**: scope enforcement is blocking (not advisory), rate limiting, `--dry-run`
- **CI/CD ready**: SARIF 2.1 output integrates with GitHub Security / GitLab dashboards

---

## Features

| Area | What it does |
|---|---|
| **Proxy** | HTTP/HTTPS interception with automatic TLS, scope enforcement, capture |
| **History** | Full request/response archive with filtering, search, export (JSON/HAR/CSV) |
| **Endpoint Map** | Auto-normalized endpoint + parameter inventory from all traffic |
| **Repeater** | Clone, edit, and replay captured requests with session/transport control |
| **Fuzzer** | Intruder-style engine: sniper, battering ram, pitchfork, cluster bomb attacks |
| **Crawler** | BFS link/JS/form discovery with optional headless Chrome (go-rod) |
| **Scanner** | 14 passive checks + 8 active probes (XSS, SQLi, IDOR, JWT, path traversal, auth bypass) |
| **Findings** | Severity/confidence/evidence, false positive tracking, one-click retest |
| **Sequencer** | Token randomness analysis: entropy, charset, sequential detection |
| **Auth** | Login profiles, cookie jars, session capture, auth macros for SSO/OAuth/MFA |
| **Import** | OpenAPI 3.x / Swagger 2.0 / Postman collection import |
| **Reports** | Markdown, HTML, JSON, SARIF 2.1.0 |
| **Browser** | Real Chrome sessions via go-rod for JS challenges, WAF bypass, cookie export |
| **Transport** | Pluggable HTTP backends: raw, fast, browser-session, browser-fetch, external |
| **Workflow** | YAML-defined state sequences for business logic testing |
| **Policy** | Rate limiting, backoff, jitter policies for production-safe testing |
| **Ops** | Jobs, audit logs, notes, project dashboard |

---
## Try it out

Windows (PowerShell)
```bash
iwr https://github.com/msdbg/AgentBurp/releases/latest/download/agentburp-windows-amd64.exe -OutFile agentburp.exe; .\agentburp.exe project create demo; .\agentburp.exe scope add "example.com" --include; .\agentburp.exe crawl start https://example.com --max-pages 20 --json; .\agentburp.exe scan passive --all --json; .\agentburp.exe findings list --json
```
Linux
```bash
wget -q https://github.com/msdbg/AgentBurp/releases/latest/download/agentburp-linux-amd64 -O agentburp && chmod +x agentburp && ./agentburp project create demo && ./agentburp scope add "example.com" --include && ./agentburp crawl start https://example.com --max-pages 20 --json && ./agentburp scan passive --all --json && ./agentburp findings list --json
```
Replace example.com / https://example.com with your-target.com / https://your-target.com. For subdomains use *.example.com

## Install

```bash
# From source
go install github.com/msdbg/AgentBurp@latest

# Or clone and build
git clone https://github.com/msdbg/AgentBurp.git
cd AgentBurp
make build
```

**Requirements:** Go 1.22+ · No CGO required · Compiles on Windows, Linux, macOS

---

## Quick Start

```bash
# Create a project
agentburp project create myapp
agentburp project open myapp

# Define scope
agentburp scope add "app.example.com" --include
agentburp scope add "*.example.com" --include

# Start intercepting proxy
agentburp proxy start --port 8080

# Or crawl directly
agentburp crawl start https://app.example.com --max-depth 5 --session sess_admin

# Passive scan all captured traffic
agentburp scan passive --all --json

# Active scan a specific endpoint
agentburp scan active --endpoint ep_XXXX --rate 5

# Review findings
agentburp findings list --severity high,medium --json
agentburp findings show sig_XXXX --json

# Generate report
agentburp report generate --format sarif --output results.sarif
agentburp report generate --format html --output report.html
```

---

## AI Agent Usage

AgentBurp is designed to be operated by AI agents autonomously:

```bash
# Every command returns structured JSON
agentburp status --json
agentburp findings list --json --severity critical,high
agentburp history list --json --limit 20

# Preview before executing (safe for autonomous agents)
agentburp scan active --endpoint ep_XXXX --dry-run --json
agentburp fuzz run job_XXXX --dry-run --json

# Body is excluded from JSON by default to protect context windows
agentburp history show req_XXXX --json              # headers + hash only
agentburp history show req_XXXX --head 2000 --json  # first 2KB of body
```

All entity IDs use stable prefixed format: `req_`, `ep_`, `sig_`, `sess_`, `job_`, etc.

---

## Scanner Coverage

### Passive Checks (14)

| Check | Severity | What it detects |
|---|---|---|
| `missing-security-headers` | Medium | Missing X-Frame-Options, X-Content-Type-Options, etc. |
| `insecure-cookies` | Medium | Missing Secure, HttpOnly, SameSite flags |
| `cors-misconfiguration` | Medium | Wildcard or overly permissive CORS origins |
| `information-disclosure` | Low–High | Stack traces, error messages, version strings in responses |
| `sensitive-data-in-url` | High | Passwords, tokens, secrets in URL query strings |
| `mixed-content` | Low | HTTP resources loaded from HTTPS pages |
| `open-redirect` | Medium | Unvalidated redirect parameters |
| `csrf-missing` | Medium | State-changing POST without CSRF token |
| `cache-control` | Low | Missing cache headers on sensitive responses |
| `hsts-missing` | Low | Missing Strict-Transport-Security header |
| `ssrf-params` | Medium | URL-like parameters susceptible to SSRF |
| `sensitive-file` | Medium | Exposed config files, backups, .env, .git |
| `credential-disclosure` | High | Credentials, API keys, tokens in response bodies |
| `csp-issues` | Low | Missing or misconfigured Content-Security-Policy |

### Active Probes (8)

| Probe | Severity | Technique |
|---|---|---|
| `reflected-xss` | High | Polyglot XSS payload injection + reflection detection |
| `sqli-error` | High | SQL error-based detection with database-specific signatures |
| `idor-signal` | High | Numeric/UUID ID manipulation + response comparison |
| `auth-bypass` | Critical | Authentication artifact detection on modified credentials |
| `stored-xss` | High | Payload storage + retrieval verification |
| `path-traversal` | High | `../` sequences with OS-specific marker detection |
| `nosql-injection` | High | MongoDB operator injection (`$ne`, `$gt`, `$regex`) |
| `jwt-alg-none` | Critical | JWT algorithm confusion (none, HS256 key confusion) |
| `admin-authz` | High | Horizontal/vertical privilege escalation via admin path probing |

---

## Project Layout

```
main.go                    Entry point
cmd/                       Cobra CLI commands (30+)
internal/
  core/                    SQLite schema (18 tables), project & job stores, IDs, config
  proxy/                   HTTP(S) MITM interception + capture addon
  scope/                   Scope enforcement engine + audit logging
  context/                 URL/parameter normalization (endpoint map)
  auth/                    Login profiles, cookie jar, session management
  authmacro/               Auth macros for SSO/OAuth/MFA flows
  crawler/                 BFS crawler (link/JS/forms, optional headless Chrome via go-rod)
  fuzzer/                  Intruder-style engine (sniper, battering ram, pitchfork, cluster bomb)
  scanner/                 14 passive checks + 8 active probes
  sequencer/               Token randomness and entropy analysis
  report/                  Markdown, HTML, JSON, SARIF 2.1.0 generators
  importer/                OpenAPI 3.x / Swagger 2.0 / Postman importers
  differ/                  Request/response structural diffing
  httpclient/              Shared rate-limited HTTP client
  transport/               Pluggable transport backends (raw, fast, browser, external)
  browser/                 Headless Chrome management via go-rod
  adaptation/              Adaptive engine for WAF/rate-limit detection
  workflow/                YAML state machine for business logic testing
  policy/                  Rate limiting and backoff policy engine
  proxyprofile/            Upstream proxy profile management
  models/                  Canonical data models (JSON schema)
  output/                  JSON/human formatting layer
gauntlet/                  Integration test servers (7 scenarios)
```

Data lives in `~/.agentburp/projects/<name>/agentburp.db` (SQLite WAL mode).

---

## Build

```bash
make build       
make test        
make lint        
make build-all   
make fmt         
make dev         
```

---

## Documentation

See [docs/](docs/) for comprehensive documentation:

- [Getting Started](docs/getting-started.md) — Installation, first project, basic workflow
- [Command Reference](docs/command-reference.md) — Every command with flags and examples
- [AI Agent Guide](docs/ai-agent-guide.md) — How to integrate AgentBurp with LLM agents
- [Architecture](docs/architecture.md) — Internal design, data model, extension points

---

## License

[MIT](LICENSE) © 2026 msdbg
