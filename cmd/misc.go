package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/importer"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/report"
	"github.com/msdbg/AgentBurp/internal/sequencer"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two requests or responses",
		Long: `Compare requests or responses to spot differences.
Useful for:
  • before/after auth comparison
  • detecting injection impact
  • validating access control differences`,
	}
	cmd.AddCommand(diffRequestsCmd(), diffResponsesCmd())
	return cmd
}

func diffRequestsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "requests <req_id_a> <req_id_b>",
		Short: "Compare two requests",
		Args:  cobra.ExactArgs(2),
		Example: `  agentburp diff requests req_abc123 req_def456 --json
  agentburp diff requests req_abc123 rreq_xyz789`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			d, err := diffObjects(db.Conn(), args[0], args[1], "request")
			if err != nil {
				return err
			}
			output.PrintAuto(d, func() { printDiffHuman(d) })
			return nil
		},
	}
}

func diffResponsesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "responses <req_id_a> <req_id_b>",
		Short: "Compare two responses",
		Args:  cobra.ExactArgs(2),
		Example: `  agentburp diff responses req_abc123 rreq_xyz789 --json
  agentburp diff responses req_abc123 req_def456`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			d, err := diffObjects(db.Conn(), args[0], args[1], "response")
			if err != nil {
				return err
			}
			output.PrintAuto(d, func() { printDiffHuman(d) })
			return nil
		},
	}
}

func newSequencerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sequencer",
		Short: "Analyze token randomness and entropy",
		Long: `Analyzes the randomness quality of tokens, session IDs, CSRF tokens,
and other cryptographic values.

Useful for detecting weak random number generators.`,
	}

	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze a set of tokens from a file",
		Example: `  agentburp sequencer analyze --input tokens.txt
  agentburp sequencer analyze --input tokens.txt --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			input, _ := cmd.Flags().GetString("input")
			if input == "" {
				return fmt.Errorf("--input <file> is required")
			}
			data, err := os.ReadFile(input)
			if err != nil {
				return err
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			var tokens []string
			for _, l := range lines {
				if t := strings.TrimSpace(l); t != "" {
					tokens = append(tokens, t)
				}
			}
			report := sequencer.Analyze(tokens)
			printTokenReport(report)
			return nil
		},
	}
	analyzeCmd.Flags().String("input", "", "file containing tokens (one per line)")

	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Extract tokens from captured traffic and analyze them",
		Example: `  agentburp sequencer capture --from header --field X-CSRF-Token
  agentburp sequencer capture --from cookie --field session
  agentburp sequencer capture --from body --field access_token --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			from, _ := cmd.Flags().GetString("from")
			if from == "" {
				from, _ = cmd.Flags().GetString("extract-from")
			}
			field, _ := cmd.Flags().GetString("field")
			endpoint, _ := cmd.Flags().GetString("endpoint")
			if from == "" || field == "" {
				return fmt.Errorf("--extract-from (header|cookie|body) and --field are required")
			}
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}

			conn := db.Conn()

			query := `SELECT resp.headers_json, resp.body_blob FROM responses resp
				JOIN requests r ON r.id = resp.request_id
				WHERE r.project_id = ?`
			argsQ := []interface{}{proj.ID}
			if endpoint != "" {
				query += " AND r.endpoint_id = ?"
				argsQ = append(argsQ, endpoint)
			}
			query += " ORDER BY resp.created_at ASC"
			rows, err := conn.Query(query, argsQ...)
			if err != nil {
				return err
			}
			defer rows.Close()

			var tokens []string
			for rows.Next() {
				var headersJSON string
				var body []byte
				if err := rows.Scan(&headersJSON, &body); err != nil {
					return err
				}
				vals := extractTokenValues(from, field, headersJSON, body)
				tokens = append(tokens, vals...)
			}
			report := sequencer.Analyze(tokens)
			printTokenReport(report)
			return nil
		},
	}
	captureCmd.Flags().String("endpoint", "", "filter by endpoint ID")
	captureCmd.Flags().String("extract-from", "header", "where to extract from: header|cookie|body")
	captureCmd.Flags().String("from", "", "alias for --extract-from")
	captureCmd.Flags().String("field", "", "field name to extract")

	cmd.AddCommand(analyzeCmd, captureCmd)
	return cmd
}

func extractTokenValues(from, field, headersJSON string, body []byte) []string {
	h := http.Header{}
	var pairs []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(headersJSON), &pairs); err == nil {
		for _, p := range pairs {
			h.Add(p.Name, p.Value)
		}
	}
	var out []string
	switch from {
	case "header":
		if v := h.Get(field); v != "" {
			out = append(out, v)
		}
	case "cookie":
		for _, raw := range h.Values("Set-Cookie") {
			parts := strings.SplitN(raw, "=", 2)
			if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), field) {
				continue
			}
			value := parts[1]
			if i := strings.IndexByte(value, ';'); i != -1 {
				value = value[:i]
			}
			out = append(out, strings.TrimSpace(value))
		}
	case "body":
		var obj map[string]interface{}
		if json.Unmarshal(body, &obj) == nil {
			if v, ok := obj[field].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func printTokenReport(report *sequencer.TokenReport) {
	output.PrintAuto(report, func() {
		fmt.Println("Token randomness analysis")
		fmt.Println("────────────────────────")
		fmt.Printf("  Sample size:       %d (unique: %d, duplicates: %d)\n",
			report.SampleSize, report.UniqueTokens, report.DuplicateTokens)
		fmt.Printf("  Avg length:        %.1f chars\n", report.AvgLength)
		fmt.Printf("  Entropy:           %.2f bits/char (total ≈ %.0f bits)\n",
			report.EntropyPerChar, report.EntropyTotal)
		fmt.Printf("  Charset:           %s\n", report.Charset)
		if len(report.CharClasses) > 0 {
			fmt.Printf("  Char classes:      lower=%d upper=%d digit=%d symbol=%d\n",
				report.CharClasses["lower"], report.CharClasses["upper"],
				report.CharClasses["digit"], report.CharClasses["symbol"])
		}
		if report.Sequential {
			fmt.Printf("  Sequential:        YES — tokens increment predictably (next ≈ %s)\n", report.PredictedNext)
		} else if report.Monotonic {
			fmt.Println("  Sequential:        partially — values increase but by irregular steps")
		}
		fmt.Printf("  Randomness rating: %s\n", strings.ToUpper(report.Rating))
		for _, n := range report.Notes {
			fmt.Printf("  Note: %s\n", n)
		}
	})
}

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import API schemas (OpenAPI, Postman)",
		Long: `Import an API schema to pre-populate the endpoint and parameter map
without requiring live traffic.

Supported formats:
  openapi   — OpenAPI 2.x (Swagger) and 3.x YAML/JSON
  postman   — Postman Collection v2.x JSON`,
	}

	openAPICmd := &cobra.Command{
		Use: "openapi <file|url>", Short: "Import OpenAPI/Swagger spec",
		Args: cobra.ExactArgs(1),
		Example: `  agentburp import openapi swagger.yaml
  agentburp import openapi https://api.example.com/openapi.json
  agentburp import openapi swagger.yaml --base-url http://127.0.0.1:8080`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImport(cmd, args[0], "openapi")
		},
	}
	openAPICmd.Flags().String("base-url", "", "override the base URL from the spec")
	openAPICmd.Flags().String("session", "", "wire session cookies/headers/tokens into imported requests (e.g. --session sess_admin)")

	postmanCmd := &cobra.Command{
		Use: "postman <file>", Short: "Import Postman collection",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImport(cmd, args[0], "postman")
		},
	}
	postmanCmd.Flags().String("base-url", "", "override the base URL from the collection")
	postmanCmd.Flags().String("session", "", "wire session cookies/headers/tokens into imported requests (e.g. --session sess_admin)")

	cmd.AddCommand(openAPICmd, postmanCmd)
	return cmd
}

func runImport(cmd *cobra.Command, source, format string) error {
	projectName := requireProject()
	db, err := openProjectDB(projectName)
	if err != nil {
		return err
	}
	defer db.Close()
	proj, err := getProject(db, projectName)
	if err != nil {
		return err
	}

	data, err := importer.LoadFileOrURL(source)
	if err != nil {
		return err
	}

	var plan *importer.Plan
	if format == "openapi" {
		plan, err = importer.ParseOpenAPI(source, data)
	} else {
		plan, err = importer.ParsePostman(source, data)
	}
	if err != nil {
		return err
	}

	baseURL, _ := cmd.Flags().GetString("base-url")
	if baseURL == "" {
		baseURL, _ = cmd.Parent().PersistentFlags().GetString("base-url")
	}
	if baseURL == "" {
		baseURL, _ = cmd.Flags().GetString("base-url")
	}
	if baseURL != "" {
		plan.SetBaseURL(baseURL)
	} else if plan.BaseURL == "" {

		if len(plan.Requests) > 0 {
			if u, err := url.Parse(plan.Requests[0].URL); err == nil && u.Host != "" {
				plan.BaseURL = u.Scheme + "://" + u.Host
			}
		}
		if plan.BaseURL == "" {
			return fmt.Errorf("no base URL in spec and --base-url not given — provide one with: --base-url https://api.example.com")
		}
	}

	if sessID, _ := cmd.Flags().GetString("session"); sessID != "" {
		store := auth.NewSessionStore(db, proj.ID)
		sess, err := store.Get(sessID)
		if err != nil || sess == nil {

			if active := auth.ActiveSessionID(proj.Name); active != "" {
				sess, _ = store.Get(active)
			}
		}
		if sess != nil {
			for i := range plan.Requests {

				if len(sess.Cookies) > 0 {
					var parts []string
					for _, c := range sess.Cookies {
						parts = append(parts, c.Name+"="+c.Value)
					}
					cookieHeader := strings.Join(parts, "; ")
					plan.Requests[i].Headers = append(plan.Requests[i].Headers, "Cookie: "+cookieHeader)
				}

				for _, h := range sess.Headers {
					plan.Requests[i].Headers = append(plan.Requests[i].Headers, h.Name+": "+h.Value)
				}

				if token, ok := sess.Tokens["Authorization"]; ok && token != "" {
					hasAuth := false
					for _, h := range plan.Requests[i].Headers {
						if strings.HasPrefix(strings.ToLower(h), "authorization:") {
							hasAuth = true
							break
						}
					}
					if !hasAuth {
						plan.Requests[i].Headers = append(plan.Requests[i].Headers, "Authorization: "+token)
					}
				}
			}
		}
	}

	if flagDryRun {
		methods := map[string]int{}
		for _, r := range plan.Requests {
			methods[r.Method]++
		}
		output.DryRun(map[string]interface{}{
			"source":           source,
			"format":           plan.Format,
			"base_url":         plan.BaseURL,
			"requests_planned": len(plan.Requests),
			"methods":          methods,
			"warnings":         plan.Warnings,
			"note":             "Would import requests into history and feed the context graph",
		})
		return nil
	}

	summary, err := importer.ImportIntoDB(db, proj, plan)
	if err != nil {
		return err
	}
	output.PrintAuto(summary, func() {
		fmt.Printf("✓ Imported %s: %d requests, %d endpoints\n", summary.Format, summary.RequestsCreated, summary.Endpoints)
		for m, n := range summary.Methods {
			fmt.Printf("  %-6s %d\n", m, n)
		}
		if len(summary.Warnings) > 0 {
			fmt.Println("Warnings:")
			for _, w := range summary.Warnings {
				fmt.Printf("  - %s\n", w)
			}
		}
	})
	return nil
}

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate security assessment reports",
		Long: `Generate comprehensive reports from findings and captured data.

Formats:
  markdown   — clean Markdown (best for AI agent handoff)
  html       — HTML with embedded evidence (best for sharing)
  json       — structured JSON (best for automation/integration)
  sarif      — SARIF 2.1 (best for CI/CD / GitHub Advanced Security)`,
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a report",
		Example: `  agentburp report generate --format markdown --output report.md
  agentburp report generate --format html --output report.html
  agentburp report generate --format sarif --output results.sarif
  agentburp report generate --format json          # stdout`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			outFile, _ := cmd.Flags().GetString("output")
			includeFP, _ := cmd.Flags().GetBool("include-fp")
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}

			rep, err := report.Load(db.Conn(), proj.ID, report.Options{
				IncludeFalsePositive: includeFP,
			})
			if err != nil {
				return err
			}

			var data []byte
			switch format {
			case "markdown":
				data, err = rep.Markdown()
			case "html":
				data, err = rep.HTML()
			case "json":
				data, err = rep.JSON()
			case "sarif":
				data, err = rep.SARIF()
			default:
				return fmt.Errorf("unknown format %q — use markdown|html|json|sarif", format)
			}
			if err != nil {
				return err
			}

			if outFile == "" {
				os.Stdout.Write(data)
				if !bytes.HasSuffix(data, []byte("\n")) {
					fmt.Println()
				}
				return nil
			}
			if err := os.WriteFile(outFile, data, 0o644); err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{
				"format":       format,
				"output":       outFile,
				"bytes":        len(data),
				"findings":     rep.Stats.Findings,
				"endpoints":    rep.Stats.Endpoints,
				"requests":     rep.Stats.Requests,
				"generated_at": rep.GeneratedAt,
			}, func() {
				fmt.Printf("✓ %s report → %s (%d bytes, %d findings)\n",
					format, outFile, len(data), rep.Stats.Findings)
			})
			return nil
		},
	}
	generateCmd.Flags().StringP("format", "f", "markdown", "output format: markdown|html|json|sarif")
	generateCmd.Flags().StringP("output", "o", "", "output file path (stdout if omitted)")
	generateCmd.Flags().Bool("include-fp", false, "include findings flagged as false positives")

	cmd.AddCommand(generateCmd)
	return cmd
}

func newNotesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notes",
		Short: "Add and manage annotations",
	}

	addCmd := &cobra.Command{
		Use: "add <text>", Short: "Add a note",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			attachTo, _ := cmd.Flags().GetString("attach-to")
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			id := core.NewID("note")
			now := core.TimestampNow()
			content := args[0]
			objType := ""
			objID := attachTo
			if attachTo != "" {
				prefix, _ := core.ParsePrefix(attachTo)
				objType = prefix
			}
			db.Conn().Exec(`
				INSERT INTO notes (id, project_id, object_type, object_id, content, created_at)
				VALUES (?, ?, ?, ?, ?, ?)`,
				id, proj.ID, objType, objID, content, now,
			)
			output.PrintAuto(map[string]string{"id": id, "content": content}, func() {
				fmt.Printf("✓ Note added: %s\n", id)
				if attachTo != "" {
					fmt.Printf("  Attached to: %s\n", attachTo)
				}
			})
			return nil
		},
	}
	addCmd.Flags().String("attach-to", "", "attach to an object ID (req_*, ep_*, sig_*, etc.)")

	listCmd := &cobra.Command{
		Use: "list", Short: "List notes",
		RunE: func(cmd *cobra.Command, args []string) error {
			objectID, _ := cmd.Flags().GetString("object")
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			query := `SELECT id, object_type, object_id, content, created_at FROM notes WHERE project_id = ?`
			qArgs := []interface{}{proj.ID}
			if objectID != "" {
				query += " AND object_id = ?"
				qArgs = append(qArgs, objectID)
			}
			query += " ORDER BY created_at DESC"
			rows, _ := db.Conn().Query(query, qArgs...)
			defer rows.Close()
			type N struct {
				ID        string `json:"id"`
				Object    string `json:"object_id,omitempty"`
				Content   string `json:"content"`
				CreatedAt string `json:"created_at"`
			}
			var notes []N
			for rows.Next() {
				var n N
				var objType string
				rows.Scan(&n.ID, &objType, &n.Object, &n.Content, &n.CreatedAt)
				notes = append(notes, n)
			}
			output.PrintAuto(notes, func() {
				for _, n := range notes {
					fmt.Printf("[%s] %s\n", core.ShortID(n.ID), n.Content)
					if n.Object != "" {
						fmt.Printf("  → %s\n", n.Object)
					}
				}
			})
			return nil
		},
	}
	listCmd.Flags().String("object", "", "filter by attached object ID")

	showCmd := &cobra.Command{
		Use: "show <note_id>", Short: "Show a note with its attachment",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			var n struct {
				ID         string `json:"id"`
				ObjectType string `json:"object_type,omitempty"`
				ObjectID   string `json:"object_id,omitempty"`
				Content    string `json:"content"`
				CreatedAt  string `json:"created_at"`
			}
			err = db.Conn().QueryRow(`
				SELECT id, object_type, object_id, content, created_at
				FROM notes WHERE id = ? AND project_id = ?`,
				args[0], proj.ID,
			).Scan(&n.ID, &n.ObjectType, &n.ObjectID, &n.Content, &n.CreatedAt)
			if err != nil {
				return fmt.Errorf("note %q not found in project", args[0])
			}
			output.PrintAuto(n, func() {
				fmt.Printf("━━━ NOTE ━━━ %s\n", n.ID)
				fmt.Printf("  Created:  %s\n", n.CreatedAt)
				if n.ObjectID != "" {
					fmt.Printf("  Attached: %s (%s)\n", n.ObjectID, n.ObjectType)
				}
				fmt.Printf("\n%s\n", n.Content)
			})
			return nil
		},
	}

	deleteCmd := &cobra.Command{
		Use: "delete <note_id>", Short: "Delete a note",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			res, err := db.Conn().Exec(
				`DELETE FROM notes WHERE id = ? AND project_id = ?`, args[0], proj.ID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return fmt.Errorf("note %q not found in project", args[0])
			}
			output.Success(fmt.Sprintf("Note %s deleted", args[0]), nil)
			return nil
		},
	}

	cmd.AddCommand(addCmd, listCmd, showCmd, deleteCmd)
	return cmd
}

func newJobsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "jobs", Short: "Manage async jobs (fuzz, crawl, scan, report)"}

	listCmd := &cobra.Command{
		Use: "list", Short: "List all jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			statusFilter, _ := cmd.Flags().GetString("status")
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			query := `SELECT id, type, status, created_at, COALESCE(finished_at,'') FROM jobs WHERE project_id = ?`
			qArgs := []interface{}{proj.ID}
			if statusFilter != "" {
				query += " AND status = ?"
				qArgs = append(qArgs, statusFilter)
			}
			query += " ORDER BY created_at DESC LIMIT 50"
			rows, _ := db.Conn().Query(query, qArgs...)
			defer rows.Close()
			type J struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Status     string `json:"status"`
				CreatedAt  string `json:"created_at"`
				FinishedAt string `json:"finished_at,omitempty"`
			}
			var jobs []J
			for rows.Next() {
				var j J
				rows.Scan(&j.ID, &j.Type, &j.Status, &j.CreatedAt, &j.FinishedAt)
				jobs = append(jobs, j)
			}
			output.PrintAuto(jobs, func() {
				if len(jobs) == 0 {
					fmt.Println("No jobs.")
					return
				}
				output.PrintTable([]string{"ID", "TYPE", "STATUS", "CREATED", "FINISHED"},
					func() [][]string {
						var r [][]string
						for _, j := range jobs {
							r = append(r, []string{core.ShortID(j.ID), j.Type, j.Status, j.CreatedAt, j.FinishedAt})
						}
						return r
					}())
			})
			return nil
		},
	}
	listCmd.Flags().String("status", "", "filter: queued|running|done|failed|cancelled")

	cancelCmd := &cobra.Command{
		Use: "cancel <job_id>", Short: "Cancel a running job",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			db.Conn().Exec(`UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE id = ?`,
				core.TimestampNow(), args[0])
			output.Success(fmt.Sprintf("Job %s cancelled", args[0]), nil)
			return nil
		},
	}

	cmd.AddCommand(listCmd, cancelCmd)
	return cmd
}

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "logs", Short: "View audit logs and event history"}

	listEvents := func(db *core.DB, proj *core.Project, afterRowID int64, limit int) ([]map[string]interface{}, int64, error) {
		query := `
			SELECT rowid, id, timestamp, actor, action, object_type, object_id, result, detail_json
			FROM events WHERE project_id = ? AND rowid > ?`
		qArgs := []interface{}{proj.ID, afterRowID}
		if limit > 0 {
			query += " ORDER BY rowid ASC LIMIT ?"
			qArgs = append(qArgs, limit)
		} else {
			query += " ORDER BY rowid ASC"
		}
		rows, err := db.Conn().Query(query, qArgs...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		var events []map[string]interface{}
		last := afterRowID
		for rows.Next() {
			var rowID int64
			var id, ts, actor, action, objType, objID, result, detailJSON string
			if err := rows.Scan(&rowID, &id, &ts, &actor, &action, &objType, &objID, &result, &detailJSON); err != nil {
				return nil, 0, err
			}
			detail := map[string]interface{}{}
			json.Unmarshal([]byte(detailJSON), &detail)
			events = append(events, map[string]interface{}{
				"id":          id,
				"timestamp":   ts,
				"actor":       actor,
				"action":      action,
				"object_type": objType,
				"object_id":   objID,
				"result":      result,
				"detail":      detail,
			})
			last = rowID
		}
		return events, last, rows.Err()
	}

	listCmd := &cobra.Command{
		Use: "list", Short: "List audit log events (newest first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			limitN, _ := cmd.Flags().GetInt("limit")
			actionFilter, _ := cmd.Flags().GetString("action")
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			query := `SELECT id, timestamp, actor, action, object_type, object_id, result
				FROM events WHERE project_id = ?`
			qArgs := []interface{}{proj.ID}
			if actionFilter != "" {
				query += " AND action = ?"
				qArgs = append(qArgs, actionFilter)
			}
			query += " ORDER BY timestamp DESC LIMIT ?"
			qArgs = append(qArgs, limitN)
			rows, err := db.Conn().Query(query, qArgs...)
			if err != nil {
				return err
			}
			defer rows.Close()
			type E struct {
				ID         string `json:"id"`
				Timestamp  string `json:"timestamp"`
				Actor      string `json:"actor"`
				Action     string `json:"action"`
				ObjectType string `json:"object_type"`
				ObjectID   string `json:"object_id"`
				Result     string `json:"result"`
			}
			var events []E
			for rows.Next() {
				var e E
				if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &e.Result); err != nil {
					return err
				}
				events = append(events, e)
			}
			output.PrintAuto(events, func() {
				if len(events) == 0 {
					fmt.Println("No events.")
					return
				}
				for _, e := range events {
					status := ""
					if e.Result != "ok" {
						status = " [" + e.Result + "]"
					}
					fmt.Printf("[%s] %s — %s %s %s%s\n",
						e.Timestamp, e.Actor, e.Action, e.ObjectType, e.ObjectID, status)
				}
			})
			return nil
		},
	}
	listCmd.Flags().Int("limit", 100, "max events to show")
	listCmd.Flags().String("action", "", "filter by action (e.g. request.send)")

	tailCmd := &cobra.Command{
		Use:   "tail",
		Short: "Tail the event log (live follow; --once to exit)",
		Long: `Stream new audit events as they are written. Defaults to following
forever (Ctrl+C to stop). Use --once to print the last N events and exit
— useful for agents and scripts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			once, _ := cmd.Flags().GetBool("once")
			count, _ := cmd.Flags().GetInt("count")
			interval, _ := cmd.Flags().GetInt("interval")
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}

			var lastRowID int64
			if once || count > 0 {
				var lastID int64
				if err := db.Conn().QueryRow(`
					SELECT COALESCE(MAX(rowid),0) FROM events WHERE project_id = ?`, proj.ID,
				).Scan(&lastID); err != nil {
					return err
				}
				if lastID > 0 {
					events, _, err := listEvents(db, proj, lastID-int64(count), 0)
					if err != nil {
						return err
					}
					printEvents(events)
					lastRowID = lastID
				}
				if once {
					return nil
				}
			}

			fmt.Println("Tailing event log... (Ctrl+C to stop)")
			tick := time.NewTicker(time.Duration(interval) * time.Millisecond)
			defer tick.Stop()
			for range tick.C {
				events, newLast, err := listEvents(db, proj, lastRowID, 500)
				if err != nil {
					return err
				}
				if len(events) > 0 {
					printEvents(events)
					lastRowID = newLast
				}
			}
			return nil
		},
	}
	tailCmd.Flags().Bool("once", false, "print the last events and exit")
	tailCmd.Flags().Int("count", 20, "events to show with --once")
	tailCmd.Flags().Int("interval", 1000, "poll interval in ms")

	exportCmd := &cobra.Command{
		Use:   "export --output <file>",
		Short: "Export all events to a file (JSON or CSV)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			outFile, _ := cmd.Flags().GetString("output")
			if outFile == "" {
				return fmt.Errorf("--output is required")
			}
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}
			events, _, err := listEvents(db, proj, 0, 0)
			if err != nil {
				return err
			}
			var data []byte
			switch format {
			case "json":
				data, err = json.MarshalIndent(events, "", "  ")
			case "csv":
				var b bytes.Buffer
				b.WriteString("id,timestamp,actor,action,object_type,object_id,result,detail\n")
				for _, e := range events {
					detail, _ := json.Marshal(e["detail"])
					fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s\n",
						e["id"], e["timestamp"], e["actor"], e["action"],
						e["object_type"], e["object_id"], e["result"], detail)
				}
				data = b.Bytes()
			default:
				return fmt.Errorf("unknown format %q — use json|csv", format)
			}
			if err != nil {
				return err
			}
			if err := os.WriteFile(outFile, data, 0o644); err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{
				"format": format, "output": outFile, "events": len(events),
			}, func() {
				fmt.Printf("✓ Exported %d events → %s\n", len(events), outFile)
			})
			return nil
		},
	}
	exportCmd.Flags().StringP("format", "f", "json", "export format: json|csv")
	exportCmd.Flags().StringP("output", "o", "", "output file path")

	cmd.AddCommand(listCmd, tailCmd, exportCmd)
	return cmd
}

func printEvents(events []map[string]interface{}) {
	if output.JSONMode {
		for _, e := range events {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
		}
		return
	}
	for _, e := range events {
		status := ""
		if e["result"] != "ok" {
			status = " [" + e["result"].(string) + "]"
		}
		fmt.Printf("[%s] %s — %s %s %s%s\n",
			e["timestamp"], e["actor"], e["action"], e["object_type"], e["object_id"], status)
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show project dashboard summary",
		Long:  `Machine-readable project status. Equivalent to Burp's dashboard. Use --json for agent consumption.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := getProject(db, projectName)
			if err != nil {
				return err
			}

			var requestCount, endpointCount, signalCount, jobCount int
			db.Conn().QueryRow(`SELECT COUNT(*) FROM requests WHERE project_id = ?`, proj.ID).Scan(&requestCount)
			db.Conn().QueryRow(`SELECT COUNT(*) FROM endpoints WHERE project_id = ?`, proj.ID).Scan(&endpointCount)
			db.Conn().QueryRow(`SELECT COUNT(*) FROM signals WHERE project_id = ? AND false_positive = 0`, proj.ID).Scan(&signalCount)
			db.Conn().QueryRow(`SELECT COUNT(*) FROM jobs WHERE project_id = ? AND status = 'running'`, proj.ID).Scan(&jobCount)

			type SevCount struct {
				Severity string `json:"severity"`
				Count    int    `json:"count"`
			}
			sevRows, _ := db.Conn().Query(`
				SELECT severity, COUNT(*) FROM signals
				WHERE project_id = ? AND false_positive = 0
				GROUP BY severity`, proj.ID)
			var sevBreakdown []SevCount
			if sevRows != nil {
				for sevRows.Next() {
					var sc SevCount
					sevRows.Scan(&sc.Severity, &sc.Count)
					sevBreakdown = append(sevBreakdown, sc)
				}
				sevRows.Close()
			}

			status := map[string]interface{}{
				"project": map[string]string{
					"id":         proj.ID,
					"name":       proj.Name,
					"created_at": proj.CreatedAt,
				},
				"stats": map[string]int{
					"requests":     requestCount,
					"endpoints":    endpointCount,
					"findings":     signalCount,
					"running_jobs": jobCount,
				},
				"findings_by_severity": sevBreakdown,
			}

			output.PrintAuto(status, func() {
				fmt.Printf("━━━ AgentBurp Status ━━━\n")
				fmt.Printf("Project:    %s (%s)\n", proj.Name, proj.ID)
				fmt.Printf("\nStats:\n")
				fmt.Printf("  Requests:      %d\n", requestCount)
				fmt.Printf("  Endpoints:     %d\n", endpointCount)
				fmt.Printf("  Findings:      %d\n", signalCount)
				fmt.Printf("  Running jobs:  %d\n", jobCount)
				if len(sevBreakdown) > 0 {
					fmt.Printf("\nFindings by severity:\n")
					for _, sc := range sevBreakdown {
						fmt.Printf("  %-10s %d\n", sc.Severity, sc.Count)
					}
				}
				fmt.Printf("\nQuick commands:\n")
				fmt.Printf("  agentburp history list --json\n")
				fmt.Printf("  agentburp endpoints list --json\n")
				fmt.Printf("  agentburp findings list --json\n")
			})
			return nil
		},
	}
}
