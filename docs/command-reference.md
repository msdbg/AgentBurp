# Command Reference

Complete reference for every AgentBurp command, organized by feature area.

> **Tip:** All commands support `--json` for machine-readable output and `-p <project>` to target a specific project.

---

## Project Management

### `agentburp project create <name>`

Create a new project. Projects are isolated containers with their own database, scope, and configuration.

```bash
agentburp project create myapp --json
```

### `agentburp project open <name>`

Set a project as the active project for subsequent commands.

```bash
agentburp project open myapp
```

### `agentburp project list`

List all projects.

```bash
agentburp project list --json
```

### `agentburp project delete <name>`

Soft-delete a project. Use `--force` for permanent deletion.

```bash
agentburp project delete myapp
agentburp project delete myapp --force    # permanent, cannot be undone
```

---

## Scope

### `agentburp scope add <pattern>`

Add a scope rule. Scope is **blocking** — out-of-scope requests are rejected.

| Flag | Description |
|---|---|
| `--include` | Include pattern in scope |
| `--exclude` | Exclude pattern from scope |
| `--type` | Pattern type: `host` (default), `url`, or `regex` |

```bash
agentburp scope add "app.example.com" --include
agentburp scope add "*.example.com" --include
agentburp scope add "https://api.example.com/v1" --include --type url
agentburp scope add ".*\.staging\..*" --exclude --type regex
```

### `agentburp scope list`

List all scope rules for the active project.

### `agentburp scope remove <rule_id>`

Remove a scope rule by ID.

---

## Proxy

### `agentburp proxy start`

Start the MITM proxy for HTTP/HTTPS interception.

| Flag | Default | Description |
|---|---|---|
| `--port` | `8080` | Listen port |
| `--host` | `127.0.0.1` | Listen host |
| `--upstream` | — | Upstream proxy URL (e.g. `http://corp-proxy:3128`) |
| `--silent` | `false` | Suppress per-request log output |

```bash
agentburp proxy start
agentburp proxy start --port 9090 --silent
agentburp proxy start --upstream http://corporate-proxy:3128
```

---

## History

### `agentburp history list`

List captured HTTP requests with filtering.

| Flag | Description |
|---|---|
| `--host` | Filter by host |
| `--method` | Filter by HTTP method |
| `--status` | Filter by response status code |
| `--source` | Filter by source: `proxy`, `repeater`, `fuzzer`, `crawler` |
| `--search` | Search in URL and path |
| `--limit` | Max results (default: 100) |

```bash
agentburp history list --json
agentburp history list --host api.example.com --method POST
agentburp history list --status 500 --limit 20
```

### `agentburp history show <req_id>`

Show a captured request/response pair. Body access is gated to protect AI context windows.

| Flag | Description |
|---|---|
| `--head N` | Return first N bytes of body |
| `--body-only` | Return full body (warns if >100KB) |
| `--headers-only` | Return headers only (fastest) |
| `--view` | Output view: `pretty`, `raw`, or `json` |

```bash
agentburp history show req_abc123 --json
agentburp history show req_abc123 --head 2000 --json
agentburp history show req_abc123 --body-only
```

### `agentburp history export`

Export history to JSON, HAR, or CSV.

| Flag | Description |
|---|---|
| `--format` | Export format: `json` (default), `har`, `csv` |
| `-o, --output` | Output file (stdout if omitted) |
| `--limit` | Max exchanges to export (0 = all) |

```bash
agentburp history export --format har --output traffic.har
```

---

## Endpoints

### `agentburp endpoints list`

List all discovered endpoints (auto-normalized from captured traffic).

| Flag | Description |
|---|---|
| `--host` | Filter by host |
| `--method` | Filter by HTTP method |
| `--path` | Filter by path (partial match) |

```bash
agentburp endpoints list --json
agentburp endpoints list --method POST --host api.example.com
```

### `agentburp endpoints show <ep_id>`

Show full endpoint details including discovered parameters.

```bash
agentburp endpoints show ep_abc123 --json
```

---

## Repeater

Clone, edit, and replay captured requests.

### `agentburp repeater clone <req_id>`

Clone a captured request for editing.

### `agentburp repeater edit <rreq_id>`

Edit a cloned request (modify headers, body, method, URL).

### `agentburp repeater compose`

Build a new request from scratch.

### `agentburp repeater send <rreq_id>`

Send a repeater request.

| Flag | Default | Description |
|---|---|---|
| `--follow-redirects` | `true` | Follow HTTP redirects |
| `--no-session` | `false` | Don't apply session credentials |
| `--session` | — | Specific session ID to use |
| `--timeout` | `30` | Request timeout in seconds |
| `--transport` | — | Transport profile: `raw-http`, `browser-session`, `fast-http`, etc. |

```bash
agentburp repeater send rreq_abc123 --json
agentburp repeater send rreq_abc123 --transport browser-session --json
agentburp repeater send rreq_abc123 --no-session --json
```

### `agentburp repeater compare <id1> <id2>`

Compare two requests or responses side by side.

---

## Fuzzer

### `agentburp fuzz run <job_id>`

Execute a fuzz job (Intruder-style attack).

| Flag | Default | Description |
|---|---|---|
| `--rate` | `10` | Max requests per second per host |
| `--concurrency` | `10` | Number of concurrent workers |

```bash
agentburp fuzz run job_abc123 --rate 10 --concurrency 5 --json
agentburp fuzz run job_abc123 --dry-run --json    # preview without sending
```

**Attack types:** sniper, battering ram, pitchfork, cluster bomb.

**Anomaly detection:** The fuzzer automatically flags responses that deviate significantly from baseline (status code, body length, response time).

---

## Crawler

### `agentburp crawl start <url>`

Start a crawl from the given URL.

| Flag | Default | Description |
|---|---|---|
| `--max-depth` | `3` | Maximum crawl depth |
| `--max-pages` | `200` | Maximum pages to fetch |
| `--concurrency` | `5` | Number of concurrent workers |
| `--headless` | `false` | Use headless Chrome (go-rod) for JS-heavy apps |
| `--session` | — | Session ID for authenticated crawling |
| `--rate` | project config | Max requests per second per host |
| `--scope` | `allowed` | Scope policy: `allowed` or `all` |
| `--proxy` | — | Route headless browsing through proxy URL |

```bash
agentburp crawl start https://app.example.com --max-depth 5 --json
agentburp crawl start https://app.example.com --headless --session sess_admin
```

### `agentburp crawl status <job_id>`

Check crawl job status.

### `agentburp crawl results <job_id>`

Show discovered pages and endpoints.

### `agentburp crawl stop <job_id>`

Stop a running crawl.

---

## Scanner

### `agentburp scan passive`

Run passive scanner on captured traffic. **No additional requests are sent.**

| Flag | Description |
|---|---|
| `--all` | Scan all captured traffic |
| `--request` | Scan a specific request by ID |

```bash
agentburp scan passive --all --json
agentburp scan passive --request req_abc123 --json
```

### `agentburp scan active`

Run active scanner — sends targeted probes to detect vulnerabilities.

| Flag | Default | Description |
|---|---|---|
| `--endpoint` | — | Endpoint ID to scan (required) |
| `--rate` | `10` | Max probes per second |
| `--safe-mode` | `true` | Only safe, non-destructive probes |
| `--allow-destructive` | `false` | Allow aggressive checks |

```bash
agentburp scan active --endpoint ep_abc123 --rate 5 --json
agentburp scan active --endpoint ep_abc123 --dry-run --json
```

### `agentburp scan status <job_id>`

Check scan job status.

### `agentburp scan results <job_id>`

Show scan results.

---

## Findings

### `agentburp findings list`

List all findings with filtering.

| Flag | Description |
|---|---|
| `--severity` | Filter: `critical`, `high`, `medium`, `low`, `info` (comma-separated) |
| `--type` | Filter: `passive`, `active`, `manual` |
| `--endpoint` | Filter by endpoint ID |

```bash
agentburp findings list --severity high,critical --json
agentburp findings list --type active --endpoint ep_abc123 --json
```

### `agentburp findings show <sig_id>`

Show full finding details with evidence.

### `agentburp findings evidence <sig_id>`

Show evidence payload for a finding.

### `agentburp findings retest <sig_id>`

Re-run the scanner check to verify if a finding still exists.

### `agentburp findings mark-fp <sig_id>`

Mark a finding as a false positive (excluded from reports).

### `agentburp findings unmark-fp <sig_id>`

Unmark a false positive.

---

## Auth

### `agentburp auth login --config <yaml>`

Authenticate using a profile config file. Supports `json_login`, `form_login`, `header`, and `cookie` types.

### `agentburp auth session list`

List all sessions.

### `agentburp auth session use <sess_id>`

Set the active session for the project. All subsequent requests (repeater, fuzzer, crawler, scanner) will use this session's credentials.

### `agentburp auth session create`

Create an empty session for manual population.

### `agentburp auth session show <sess_id>`

Show session details (cookies, headers, tokens).

### `agentburp auth session delete <sess_id>`

Delete a session.

### `agentburp auth macro`

Auth macro engine for complex SSO/OAuth/MFA flows.

---

## Import

### `agentburp import openapi <file|url>`

Import an OpenAPI 3.x or Swagger 2.0 specification.

| Flag | Description |
|---|---|
| `--base-url` | Override the base URL from the spec |
| `--session` | Wire session credentials into imported requests |

```bash
agentburp import openapi swagger.yaml --base-url http://127.0.0.1:8080
agentburp import openapi https://api.example.com/openapi.json --session sess_admin
```

### `agentburp import postman <file>`

Import a Postman collection.

| Flag | Description |
|---|---|
| `--base-url` | Override the base URL |
| `--session` | Wire session credentials |

---

## Reports

### `agentburp report generate`

Generate a security assessment report.

| Flag | Default | Description |
|---|---|---|
| `-f, --format` | `markdown` | Format: `markdown`, `html`, `json`, `sarif` |
| `-o, --output` | stdout | Output file path |
| `--include-fp` | `false` | Include findings marked as false positives |

```bash
agentburp report generate --format sarif --output results.sarif
agentburp report generate --format html --output report.html
agentburp report generate --format json    
```

---

## Sequencer

### `agentburp sequencer capture`

Extract tokens from stored responses.

| Flag | Description |
|---|---|
| `--extract-from` | Where to extract: `header`, `cookie`, or `body` |
| `--field` | Field name to extract |
| `--endpoint` | Filter by endpoint ID |

```bash
agentburp sequencer capture --from header --field X-CSRF-Token --json
agentburp sequencer capture --from cookie --field session --json
```

### `agentburp sequencer analyze --input <file>`

Analyze a set of tokens from a file (one per line).

```bash
agentburp sequencer analyze --input tokens.txt --json
```

---

## Utilities

### `agentburp decode`

Encode, decode, and hash utilities: `base64`, `url`, `hex`, `hash`.

### `agentburp diff requests <id1> <id2>`

Compare two requests structurally (method, headers, body, URL).

### `agentburp diff responses <id1> <id2>`

Compare two responses structurally (status, headers, body).

---

## Operations

### `agentburp status`

Show project dashboard summary (requests, endpoints, findings, active jobs).

### `agentburp jobs list`

List all async jobs. Filter with `--status queued|running|done|failed|cancelled`.

### `agentburp jobs cancel <job_id>`

Cancel a running job.

### `agentburp logs list`

List audit log events. Filter with `--action` and `--limit`.

### `agentburp logs tail`

Stream new audit events. Use `--once` to print last N events and exit.

| Flag | Default | Description |
|---|---|---|
| `--once` | `false` | Print last events and exit |
| `--count` | `20` | Events to show with `--once` |
| `--interval` | `1000` | Poll interval in ms |

### `agentburp logs export`

Export events to JSON or CSV.

### `agentburp notes add <text>`

Add a note, optionally attached to an object via `--attach-to <id>`.

### `agentburp notes list`

List notes. Filter with `--object <id>`.

---

## Advanced

### Transport Profiles

Transport profiles define HOW requests are sent.

| Type | Description |
|---|---|
| `raw-http` | Standard Go net/http |
| `fast-http` | High-throughput tuned client |
| `browser-session` | Uses cookies from real browser session |
| `browser-fetch` | Executes request inside real browser (fetch/XHR) |
| `external-transport` | Custom TLS / proxy chain adapter |

```bash
agentburp transport create --name stealth --type browser-session
agentburp transport list --json
```

### Browser Sessions

Manage real Chrome instances for JS challenges and WAF bypass.

```bash
agentburp browser open https://target.example.com/login --json
agentburp browser cookies export --session dashboard-session --json
agentburp browser execute "document.cookie" --json
agentburp browser close --json
```

### Policies

Rate limiting and backoff policies for production-safe testing.

```bash
agentburp policy create --file careful.yaml
agentburp policy use careful_production
```

### Workflows

YAML-defined state sequences for business logic testing.

```yaml
name: checkout_state
steps:
  - name: create_cart
    request: { method: POST, url: https://app.example.com/api/cart }
    extract: { cart_id: "$.cart.id" }
  - name: add_item
    request: { method: POST, url: "https://app.example.com/api/cart/{{cart_id}}/items", json: {item_id: 1001} }
```

```bash
agentburp workflow create --file checkout.yaml --json
agentburp workflow run wf_abc123 --json
agentburp workflow run wf_abc123 --dry-run --json
```

### Proxy Profiles

Upstream proxy routing for authorized engagements.

```bash
agentburp proxy-profile create --name corp --type http --url http://proxy:3128
agentburp proxy-profile use corp
agentburp proxy-profile check corp
```

### Detections & Adaptation

Monitor WAF/anti-bot blocks and adapt automatically.

```bash
agentburp detections summary --json
agentburp adapt status --json
agentburp adapt rules --json
```
