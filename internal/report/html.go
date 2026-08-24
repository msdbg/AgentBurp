package report

import (
	"bytes"
	"encoding/json"
	"html/template"
)

func (r *Report) HTML() ([]byte, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"jsonPretty": func(v map[string]interface{}) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return "{}"
			}
			return string(b)
		},
		"sevClass": func(s string) string { return "sev-" + s },
	}).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report — {{.Project.Name}}</title>
<style>
  :root { --critical:#b91c1c; --high:#ea580c; --medium:#d97706; --low:#2563eb; --info:#64748b; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; background:#f8fafc; color:#0f172a; }
  header { background:#0f172a; color:#fff; padding:24px 32px; }
  header h1 { margin:0; font-size:22px; }
  header p { margin:4px 0 0; color:#94a3b8; font-size:13px; }
  main { max-width: 980px; margin: 24px auto; padding: 0 16px 64px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin:16px 0 32px; }
  .card { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:14px 20px; min-width:130px; }
  .card .num { font-size:24px; font-weight:700; }
  .card .lbl { font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:.04em; }
  h2 { border-bottom:2px solid #e2e8f0; padding-bottom:6px; margin-top:36px; }
  .badge { display:inline-block; padding:2px 10px; border-radius:999px; color:#fff; font-size:12px; font-weight:600; }
  .sev-critical{background:var(--critical)} .sev-high{background:var(--high)}
  .sev-medium{background:var(--medium)} .sev-low{background:var(--low)} .sev-info{background:var(--info)}
  .finding { background:#fff; border:1px solid #e2e8f0; border-left:5px solid #cbd5e1; border-radius:6px; padding:16px 20px; margin:14px 0; }
  .finding.sev-critical{border-left-color:var(--critical)} .finding.sev-high{border-left-color:var(--high)}
  .finding.sev-medium{border-left-color:var(--medium)} .finding.sev-low{border-left-color:var(--low)}
  .finding.sev-info{border-left-color:var(--info)}
  .finding h3 { margin:0 0 8px; font-size:16px; }
  .meta { font-size:13px; color:#475569; margin:2px 0; }
  pre { background:#0f172a; color:#e2e8f0; padding:12px; border-radius:6px; overflow-x:auto; font-size:12px; }
  table { width:100%; border-collapse:collapse; background:#fff; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #e2e8f0; }
  th { background:#f1f5f9; }
  footer { color:#94a3b8; font-size:12px; text-align:center; margin-top:48px; }
</style>
</head>
<body>
<header>
  <h1>Security Assessment Report — {{.Project.Name}}</h1>
  <p>Project {{.Project.ID}} · generated {{.GeneratedAt}} · {{.Stats.Requests}} requests / {{.Stats.Endpoints}} endpoints</p>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="num">{{.Stats.Requests}}</div><div class="lbl">Requests</div></div>
    <div class="card"><div class="num">{{.Stats.Endpoints}}</div><div class="lbl">Endpoints</div></div>
    <div class="card"><div class="num">{{.Stats.Findings}}</div><div class="lbl">Findings</div></div>
    <div class="card"><div class="num">{{.Stats.Notes}}</div><div class="lbl">Notes</div></div>
  </div>

  <h2>Findings by severity</h2>
  {{if .Findings}}
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {{range .SortedSeverities}}<tr><td><span class="badge sev-{{.}}">{{.}}</span></td><td>{{index $.FindingsBySeverity .}}</td></tr>{{end}}
  </table>
  {{else}}<p>No findings.</p>{{end}}

  <h2>Findings ({{len .Findings}})</h2>
  {{range .Findings}}
  <div class="finding sev-{{.Severity}}">
    <h3>{{.Title}} <span class="badge sev-{{.Severity}}">{{.Severity}}</span></h3>
    <p class="meta"><strong>Check:</strong> {{.Type}}/{{.CheckID}} · <strong>Confidence:</strong> {{.Confidence}} · <strong>Reported:</strong> {{.CreatedAt}}</p>
    {{if .EndpointID}}<p class="meta"><strong>Endpoint:</strong> {{.EndpointURL}} ({{.EndpointID}}){{if gt .ResponseCode 0}} · HTTP {{.ResponseCode}}{{end}}</p>{{end}}
    {{if .RequestID}}<p class="meta"><strong>Request:</strong> {{.RequestID}}{{if .RequestURL}} — {{.RequestURL}}{{end}}</p>{{end}}
    {{if .Retested}}<p class="meta"><strong>Retested:</strong> yes — re-verified</p>{{end}}
    {{if .Explanation}}<p><strong>Explanation:</strong> {{.Explanation}}</p>{{end}}
    {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
    {{if .Evidence}}<details><summary>Evidence</summary><pre>{{jsonPretty .Evidence}}</pre></details>{{end}}
  </div>
  {{end}}

  {{if .Endpoints}}
  <h2>Endpoints ({{len .Endpoints}})</h2>
  <table>
    <tr><th>Method</th><th>Path</th><th>Host</th><th>Requests</th><th>Last seen</th></tr>
    {{range .Endpoints}}<tr><td>{{.Method}}</td><td>{{.PathTemplate}}</td><td>{{.Host}}</td><td>{{.RequestCount}}</td><td>{{.LastSeen}}</td></tr>{{end}}
  </table>
  {{end}}

  {{if .Notes}}
  <h2>Notes ({{len .Notes}})</h2>
  <ul>{{range .Notes}}<li><code>{{.ID}}</code>{{if .ObjectID}} → <code>{{.ObjectID}}</code>{{end}}: {{.Content}}</li>{{end}}</ul>
  {{end}}

  {{if .Scope}}
  <h2>Scope</h2>
  <ul>{{range .Scope}}<li><strong>{{.Action}}</strong> ({{.PatternType}}): <code>{{.Pattern}}</code></li>{{end}}</ul>
  {{end}}

  <footer>Generated by AgentBurp</footer>
</main>
</body>
</html>`
