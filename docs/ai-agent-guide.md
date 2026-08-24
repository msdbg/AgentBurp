# AI Agent Integration Guide

AgentBurp is designed for AI agents. This guide covers integration patterns, best practices, and common workflows for LLM-based security agents.

---

## Design Principles

AgentBurp follows three rules that make it agent-friendly:

1. **Every command returns JSON** — use `--json` on any command
2. **Every mutating command supports `--dry-run`** — preview before executing
3. **Body is excluded by default** — protects your context window from multi-megabyte HTML blobs

---

## JSON Output

Every command supports `--json`. The output is always a single JSON object or array.

```bash
agentburp status --json
```

```json
{
  "project": "myapp",
  "project_id": "proj_XWzg5a2W82wD",
  "requests": 104,
  "endpoints": 40,
  "findings": 12,
  "active_session": "sess_admin",
  "jobs_running": 0
}
```

### Body Gating

Request/response bodies are excluded from JSON output by default to protect agent context windows. Control access explicitly:

```bash
# Default: headers + body_hash + body_size (no body content)
agentburp history show req_abc123 --json

# First 2KB of body
agentburp history show req_abc123 --head 2000 --json

# Full body (use with caution)
agentburp history show req_abc123 --body-only --json

# Headers only (fastest)
agentburp history show req_abc123 --headers-only --json
```

### Entity IDs

All entities use stable prefixed IDs. Parse the prefix to determine the object type:

| Prefix | Type | Example |
|---|---|---|
| `proj_` | Project | `proj_XWzg5a2W82wD` |
| `req_` | Request | `req_EdGX3kG1XVQf` |
| `resp_` | Response | `resp_7kM2Qn9pLwXY` |
| `ep_` | Endpoint | `ep_gLQNN9z4bYZK` |
| `sess_` | Session | `sess_admin_x9Kp` |
| `job_` | Job | `job_crawl_H4mN` |
| `sig_` | Finding | `sig_xss_PqR7vN` |
| `evt_` | Event | `evt_scope_m2Wp` |
| `note_` | Note | `note_review_Y3kL` |

---

## Autonomous Workflow

This is an example of autonomous workflow an AI agent might execute:

### Phase 1: Setup

```bash
# Create project and define scope
agentburp project create target_app --json
agentburp project open target_app
agentburp scope add "app.example.com" --include --json
agentburp scope add "api.example.com" --include --json
```

### Phase 2: Authentication

```bash
# Login and capture session
agentburp auth login --config auth.yaml --json
# → Returns sess_id

agentburp auth session use sess_XXXX --json
```

### Phase 3: Discovery

```bash
# Crawl the application
agentburp crawl start https://app.example.com --max-depth 5 --session sess_XXXX --json
# → Returns job_id

# Poll for completion
agentburp crawl status job_XXXX --json
# → {"status": "done", "pages_found": 47}

# Review discovered endpoints
agentburp endpoints list --json
```

### Phase 4: Scanning

```bash
# Passive scan all traffic (fast, no additional requests)
agentburp scan passive --all --json

# Active scan high-value endpoints
agentburp scan active --endpoint ep_XXXX --rate 5 --json
```

### Phase 5: Analysis

```bash
# List findings by severity
agentburp findings list --severity critical,high --json

# Examine a specific finding
agentburp findings show sig_XXXX --json

# View the evidence
agentburp findings evidence sig_XXXX --json

# Verify finding is real
agentburp findings retest sig_XXXX --json

# Mark false positives
agentburp findings mark-fp sig_XXXX --json
```

### Phase 6: Reporting

```bash
# Generate SARIF for CI/CD
agentburp report generate --format sarif --output results.sarif

# Generate human-readable report
agentburp report generate --format html --output report.html
```

---

## Safety Guards

AgentBurp includes multiple safety mechanisms for autonomous operation:

### Scope Enforcement

Scope is **blocking, not advisory**. Any request to an out-of-scope URL is rejected and logged to the audit trail.

```bash
# Define scope before any testing
agentburp scope add "target.example.com" --include --json

# Verify scope
agentburp scope list --json
```

### Dry Run

Preview any mutating operation before executing:

```bash
agentburp scan active --endpoint ep_XXXX --dry-run --json
# → Shows what probes would be sent, without sending them

agentburp fuzz run job_XXXX --dry-run --json
# → Shows payload combinations and target URLs

agentburp crawl start https://example.com --dry-run --json
# → Shows configuration and scope check
```

### Rate Limiting

Built-in per-host rate limiting prevents overwhelming targets:

```bash
# Set rate limit
agentburp scan active --endpoint ep_XXXX --rate 5    # 5 req/sec max

# Or use policies for production
agentburp policy create --file careful.yaml
agentburp policy use careful_production
```

### Audit Trail

Every action is logged with full context:

```bash
# View recent events
agentburp logs tail --once --count 50 --json

# Filter by action type
agentburp logs list --action scope.violation --json
```

---

## Direct Database Access

AgentBurp stores everything in SQLite. An agent can query the database directly:

```bash
# Database location
~/.agentburp/projects/<name>/agentburp.db
```

```sql
-- Find all POST endpoints with parameters
SELECT e.id, e.method, e.path, p.name, p.location
FROM endpoints e
JOIN params p ON p.endpoint_id = e.id
WHERE e.method = 'POST';

-- Get high-severity findings with evidence
SELECT s.id, s.title, s.severity, s.evidence_json
FROM signals s
WHERE s.severity IN ('high', 'critical')
  AND s.false_positive = 0;

-- Count requests by host
SELECT host, COUNT(*) as count
FROM requests
GROUP BY host
ORDER BY count DESC;
```

### Key Tables

| Table | Purpose |
|---|---|
| `projects` | Project metadata and config |
| `requests` | Captured HTTP requests |
| `responses` | Captured HTTP responses |
| `endpoints` | Normalized endpoint map |
| `params` | Discovered parameters per endpoint |
| `signals` | Security findings |
| `scope_rules` | Scope include/exclude rules |
| `sessions` | Authentication sessions |
| `events` | Audit log |
| `jobs` | Async job tracking |
| `notes` | Annotations |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install AgentBurp
        run: go install github.com/msdbg/AgentBurp@latest

      - name: Start target
        run: docker-compose up -d

      - name: Run scan
        run: |
          agentburp project create ci-scan
          agentburp project open ci-scan
          agentburp scope add "localhost" --include
          agentburp import openapi swagger.yaml --base-url http://localhost:8080
          agentburp scan passive --all --json
          agentburp report generate --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Error Handling

Commands return non-zero exit codes on failure. JSON errors include an `error` field:

```json
{
  "error": "project \"nonexistent\" not found"
}
```

Common exit codes:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | General error (invalid args, not found, etc.) |

---

## Tips for Agent Developers

1. **Always use `--json`** — parsing human-readable tables is fragile
2. **Use `--dry-run` first** — especially for active scans and fuzzing
3. **Gate body access** — use `--head 2000` instead of `--body-only` to save context
4. **Check scope before testing** — `agentburp scope list --json`
5. **Monitor the audit trail** — `agentburp logs tail --once --count 10 --json`
6. **Use stable IDs** — every object has a persistent prefixed ID, store them
7. **Rate limit appropriately** — default is 10 req/sec, lower for production targets
