# Getting Started

This guide walks you through installing AgentBurp creating your first project, and running your first security scan.

## Installation

### From Source (Recommended)

```bash
go install github.com/msdbg/AgentBurp@latest
```

### Clone and Build

```bash
git clone https://github.com/msdbg/AgentBurp.git
cd AgentBurp
make build
```

This produces `agentburp` (or `agentburp.exe` on Windows).

### Cross-Compile

```bash
make build-all    
```

### Requirements

- Go 1.22+
- No CGO required (pure-Go SQLite via `modernc.org/sqlite`)
- Works on Windows, Linux, macOS

### Verify Installation

```bash
agentburp version

```

---

## Core Concepts

### Projects

Everything in AgentBurp lives inside a **project**. A project has its own SQLite database, scope rules, sessions, and configuration.

```bash
agentburp project create myapp
agentburp project open myapp
agentburp project list --json
```

Projects are stored at `~/.agentburp/projects/<name>/agentburp.db`.

### Scope

Scope defines which hosts/URLs the tool is allowed to interact with. **Scope is blocking, not advisory** out-of-scope requests are rejected at every layer.

```bash
# Include a host (supports wildcards)
agentburp scope add "app.example.com" --include
agentburp scope add "*.example.com" --include

# Include a URL prefix
agentburp scope add "https://api.example.com/v1" --include --type url

# Exclude specific paths
agentburp scope add ".*\\.staging\\..*" --exclude --type regex

# View current scope
agentburp scope list --json
```

### IDs

Every object in AgentBurp has a prefixed, collision-resistant ID:

| Prefix | Object |
|---|---|
| `proj_` | Project |
| `req_` | Request |
| `resp_` | Response |
| `ep_` | Endpoint |
| `sess_` | Session |
| `job_` | Job |
| `sig_` | Finding/Signal |
| `evt_` | Audit event |
| `note_` | Note |

IDs are stable and never recycled. Use them to reference objects across commands.

### Global Flags

Every command supports these flags:

| Flag | Purpose |
|---|---|
| `--json` | Machine-readable JSON output (for AI agents and scripts) |
| `--dry-run` | Preview what would happen without executing |
| `--no-color` | Disable color output |
| `-p, --project` | Target a specific project by name or ID |

---

## First Scan Walkthrough

### Step 1: Create a Project

```bash
agentburp project create dvwa
agentburp project open dvwa
```

### Step 2: Define Scope

```bash
agentburp scope add "127.0.0.1" --include
```

### Step 3: Capture Traffic

**Option A: Proxy**

```bash
agentburp proxy start --port 8080
```

**Option B: Crawler**

```bash
agentburp crawl start http://127.0.0.1:4280 --max-depth 3 --max-pages 100
```

**Option C: Import API spec**

```bash
agentburp import openapi swagger.yaml --base-url http://127.0.0.1:4280
```

### Step 4: Review What Was Captured

```bash
# List captured requests
agentburp history list --json

# View endpoint map
agentburp endpoints list --json

# View a specific request
agentburp history show req_XXXX --head 2000 --json
```

### Step 5: Passive Scan

```bash
agentburp scan passive --all --json
```

This runs all 14 passive checks against captured traffic, no additional requests are sent.

### Step 6: Active Scan

```bash
# Scan a specific endpoint
agentburp scan active --endpoint ep_XXXX --rate 5 --json

# Check scan progress
agentburp scan status job_XXXX --json

# View results
agentburp scan results job_XXXX --json
```

### Step 7: Review Findings

```bash
# List all findings by severity
agentburp findings list --severity high,critical --json

# View full details with evidence
agentburp findings show sig_XXXX --json

# View the evidence payload
agentburp findings evidence sig_XXXX --json

# Mark false positive
agentburp findings mark-fp sig_XXXX

# Re-test a finding
agentburp findings retest sig_XXXX --json
```

### Step 8: Generate Report

```bash
# SARIF for CI/CD integration
agentburp report generate --format sarif --output results.sarif

# HTML for humans
agentburp report generate --format html --output report.html

# Markdown for docs
agentburp report generate --format markdown --output report.md

# JSON for programmatic processing
agentburp report generate --format json
```

---

## Authentication

AgentBurp supports multiple auth methods:

### Login Profiles (YAML)

```yaml
name: dvwa_admin
type: form_login
url: http://127.0.0.1:4280/login.php
method: POST
body:
  username: admin
  password: password
capture:
  cookies: true
```

```bash
agentburp auth login --config dvwa-login.yaml --json
agentburp auth session use sess_XXXX
```

### Manual Session Creation

```bash
# Create an empty session
agentburp auth session create --name "admin" --json

# Set it as active
agentburp auth session use sess_XXXX

# All subsequent commands (crawl, fuzz, scan) will use this session
```

### Browser-Based Auth

For targets with JS-heavy login flows:

```bash
agentburp browser open http://app.example.com/login --json
# Log in manually in the browser
agentburp browser cookies export --session browser-auth --json
agentburp auth session use sess_XXXX
```

---

## Others

- [Command Reference](command-reference.md) — Every command, flag, and example
- [AI Agent Guide](ai-agent-guide.md) — Integration patterns for LLM agents
- [Architecture](architecture.md) — Internal design and data model
