package cmd

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newHistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Browse captured HTTP request history",
		Long: `HTTP history contains all requests captured by the proxy, repeater, and crawler.

Bodies are NOT returned by default to protect AI agent context windows.
Use --head N or --body-only to access body content surgically.`,
	}
	cmd.AddCommand(
		historyListCmd(),
		historyShowCmd(),
		historyRequestCmd(),
		historyResponseCmd(),
		historySearchCmd(),
		historyExportCmd(),
	)
	return cmd
}

func historyListCmd() *cobra.Command {
	var (
		filterHost   string
		filterMethod string
		filterStatus int
		filterSource string
		filterSearch string
		limit        int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List captured HTTP requests",
		Example: `  agentburp history list --json
  agentburp history list --host api.example.com --method POST
  agentburp history list --status 500 --limit 20
  agentburp history list --search "admin"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			proj, err := core.NewProjectStore(db).Get(projectName)
			if err != nil {
				return err
			}

			query := `
				SELECT r.id, COALESCE(rsp.id,''), r.method, r.url,
				       COALESCE(rsp.status_code,0), COALESCE(rsp.content_type,''),
				       COALESCE(rsp.length_bytes,0), COALESCE(rsp.time_ms,0),
				       r.source, COALESCE(r.endpoint_id,''), r.created_at
				FROM requests r
				LEFT JOIN responses rsp ON rsp.request_id = r.id
				WHERE r.project_id = ?`

			args2 := []interface{}{proj.ID}

			if filterHost != "" {
				query += " AND r.host = ?"
				args2 = append(args2, filterHost)
			}
			if filterMethod != "" {
				query += " AND UPPER(r.method) = UPPER(?)"
				args2 = append(args2, filterMethod)
			}
			if filterStatus != 0 {
				query += " AND rsp.status_code = ?"
				args2 = append(args2, filterStatus)
			}
			if filterSource != "" {
				query += " AND r.source = ?"
				args2 = append(args2, filterSource)
			}
			if filterSearch != "" {
				query += " AND (r.url LIKE ? OR r.path LIKE ?)"
				args2 = append(args2, "%"+filterSearch+"%", "%"+filterSearch+"%")
			}

			query += " ORDER BY r.created_at DESC"
			if limit > 0 {
				query += fmt.Sprintf(" LIMIT %d", limit)
			}

			rows, err := db.Conn().Query(query, args2...)
			if err != nil {
				return err
			}
			defer rows.Close()

			var entries []models.HistoryEntry
			for rows.Next() {
				var e models.HistoryEntry
				if err := rows.Scan(
					&e.RequestID, &e.ResponseID, &e.Method, &e.URL,
					&e.StatusCode, &e.ContentType, &e.BodySize, &e.TimeMs,
					&e.Source, &e.EndpointID, &e.CreatedAt,
				); err != nil {
					return err
				}
				entries = append(entries, e)
			}
			if err := rows.Err(); err != nil {
				return err
			}

			output.PrintAuto(entries, func() {
				if len(entries) == 0 {
					fmt.Println("No requests captured yet.")
					fmt.Println("Start the proxy: agentburp proxy start")
					return
				}
				headers := []string{"ID", "METHOD", "STATUS", "URL", "SIZE", "TIME(ms)", "SOURCE"}
				var tableRows [][]string
				for _, e := range entries {
					status := ""
					if e.StatusCode != 0 {
						status = strconv.Itoa(e.StatusCode)
					}
					size := ""
					if e.BodySize > 0 {
						size = humanBytes(e.BodySize)
					}
					timeMs := ""
					if e.TimeMs > 0 {
						timeMs = fmt.Sprintf("%d", e.TimeMs)
					}
					url := e.URL
					if len(url) > 80 {
						url = url[:77] + "..."
					}
					tableRows = append(tableRows, []string{
						core.ShortID(e.RequestID), e.Method, status, url, size, timeMs, e.Source,
					})
				}
				output.PrintTable(headers, tableRows)
				fmt.Printf("\n%d requests\n", len(entries))
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&filterHost, "host", "", "filter by host")
	cmd.Flags().StringVar(&filterMethod, "method", "", "filter by HTTP method")
	cmd.Flags().IntVar(&filterStatus, "status", 0, "filter by response status code")
	cmd.Flags().StringVar(&filterSource, "source", "", "filter by source (proxy|repeater|fuzzer|crawler)")
	cmd.Flags().StringVar(&filterSearch, "search", "", "search in URL and path")
	cmd.Flags().IntVar(&limit, "limit", 100, "max results to return (0 = unlimited)")
	return cmd
}

func historyShowCmd() *cobra.Command {
	var (
		view        string
		headN       int
		bodyOnly    bool
		headersOnly bool
	)
	cmd := &cobra.Command{
		Use:   "show <req_id>",
		Short: "Show a request and its response",
		Long: `Show a captured request+response pair.

Body access (to protect AI agent context windows):
  Default:       headers + body_hash + body_size only
  --head N:      first N bytes of the body
  --body-only:   full response body (warns if >100KB)
  --headers-only: headers only (fastest)`,
		Args: cobra.ExactArgs(1),
		Example: `  agentburp history show req_abc123 --json
  agentburp history show req_abc123 --head 2000
  agentburp history show req_abc123 --body-only
  agentburp history show req_abc123 --view pretty`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			reqID := args[0]

			req, err := fetchRequest(db.Conn(), reqID, headN, bodyOnly)
			if err != nil {
				return err
			}

			resp, err := fetchResponse(db.Conn(), reqID, headN, bodyOnly)
			if err != nil && err != sql.ErrNoRows {
				return err
			}

			type ShowResult struct {
				Request  *models.Request  `json:"request"`
				Response *models.Response `json:"response,omitempty"`
			}

			result := ShowResult{Request: req, Response: resp}
			output.PrintAuto(result, func() {
				printRequestHuman(req, view)
				if resp != nil {
					printResponseHuman(resp, view)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&view, "view", "pretty", "output view: pretty|raw|json")
	cmd.Flags().IntVar(&headN, "head", 0, "return first N bytes of body (0 = no body)")
	cmd.Flags().BoolVar(&bodyOnly, "body-only", false, "return full body (warns if >100KB)")
	cmd.Flags().BoolVar(&headersOnly, "headers-only", false, "return headers only")
	return cmd
}

func historyRequestCmd() *cobra.Command {
	var headN int
	cmd := &cobra.Command{
		Use:   "request <req_id>",
		Short: "Show only the request (not the response)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			req, err := fetchRequest(db.Conn(), args[0], headN, false)
			if err != nil {
				return err
			}
			output.PrintAuto(req, func() { printRequestHuman(req, "pretty") })
			return nil
		},
	}
	cmd.Flags().IntVar(&headN, "head", 0, "return first N bytes of body")
	return cmd
}

func historyResponseCmd() *cobra.Command {
	var headN int
	var bodyOnly bool
	cmd := &cobra.Command{
		Use:   "response <req_id>",
		Short: "Show only the response for a request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			resp, err := fetchResponse(db.Conn(), args[0], headN, bodyOnly)
			if err != nil {
				return err
			}
			output.PrintAuto(resp, func() { printResponseHuman(resp, "pretty") })
			return nil
		},
	}
	cmd.Flags().IntVar(&headN, "head", 4096, "return first N bytes of body (default: 4096)")
	cmd.Flags().BoolVar(&bodyOnly, "body-only", false, "return full body")
	return cmd
}

func historySearchCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Full-text search across URL, path, and headers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Delegate to list with --search
			flagProject = requireProject()
			db, err := openProjectDB(flagProject)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := core.NewProjectStore(db).Get(flagProject)
			if err != nil {
				return err
			}
			q := "%" + args[0] + "%"
			rows, err := db.Conn().Query(`
				SELECT r.id, COALESCE(rsp.id,''), r.method, r.url,
				       COALESCE(rsp.status_code,0), COALESCE(rsp.content_type,''),
				       COALESCE(rsp.length_bytes,0), COALESCE(rsp.time_ms,0),
				       r.source, COALESCE(r.endpoint_id,''), r.created_at
				FROM requests r
				LEFT JOIN responses rsp ON rsp.request_id = r.id
				WHERE r.project_id = ? AND (r.url LIKE ? OR r.path LIKE ? OR r.headers_json LIKE ?)
				ORDER BY r.created_at DESC LIMIT ?`,
				proj.ID, q, q, q, limit,
			)
			if err != nil {
				return err
			}
			defer rows.Close()
			var entries []models.HistoryEntry
			for rows.Next() {
				var e models.HistoryEntry
				rows.Scan(&e.RequestID, &e.ResponseID, &e.Method, &e.URL,
					&e.StatusCode, &e.ContentType, &e.BodySize, &e.TimeMs,
					&e.Source, &e.EndpointID, &e.CreatedAt)
				entries = append(entries, e)
			}
			output.PrintAuto(entries, func() {
				fmt.Printf("Found %d results for %q\n\n", len(entries), args[0])
				for _, e := range entries {
					fmt.Printf("  %s  %s %s → %d\n", core.ShortID(e.RequestID), e.Method, e.URL, e.StatusCode)
				}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "max results")
	return cmd
}

func historyExportCmd() *cobra.Command {
	var (
		format  string
		outFile string
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export history to JSON, HAR, or CSV",
		Example: `  agentburp history export --format json --output history.json
  agentburp history export --format har --output traffic.har
  agentburp history export --format csv --output history.csv --limit 500`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := core.NewProjectStore(db).Get(projectName)
			if err != nil {
				return err
			}

			rows, err := db.Conn().Query(`
				SELECT r.id, r.method, r.url, r.headers_json, COALESCE(r.body_blob,''),
				       COALESCE(rsp.id,''), COALESCE(rsp.status_code,0), COALESCE(rsp.reason,''),
				       COALESCE(rsp.headers_json,'[]'), COALESCE(rsp.body_blob,''),
				       COALESCE(rsp.content_type,''), COALESCE(rsp.length_bytes,0),
				       COALESCE(rsp.time_ms,0), r.source, r.created_at
				FROM requests r
				LEFT JOIN responses rsp ON rsp.request_id = r.id
				WHERE r.project_id = ?
				ORDER BY r.created_at DESC`, proj.ID)
			if err != nil {
				return err
			}
			defer rows.Close()

			var exchanges []historyExchange
			for rows.Next() {
				var e historyExchange
				rows.Scan(&e.ReqID, &e.Method, &e.URL, &e.ReqHeaders, &e.ReqBody,
					&e.RespID, &e.Status, &e.Reason, &e.RespHeaders, &e.RespBody,
					&e.ContentType, &e.Length, &e.TimeMs, &e.Source, &e.CreatedAt)
				exchanges = append(exchanges, e)
			}
			if limit > 0 && len(exchanges) > limit {
				exchanges = exchanges[:limit]
			}

			var data interface{}
			switch format {
			case "json":
				data = buildJSONExport(exchanges)
			case "har":
				data = buildHARExport(exchanges)
			case "csv":
				data = buildCSVExport(exchanges)
			default:
				return fmt.Errorf("unsupported format %q — use json|har|csv", format)
			}

			if outFile != "" {
				payload, _ := json.MarshalIndent(data, "", "  ")
				if format == "csv" {
					payload = []byte(data.(string))
				}
				if err := os.WriteFile(outFile, payload, 0o644); err != nil {
					return fmt.Errorf("write export: %w", err)
				}
				output.PrintAuto(map[string]interface{}{
					"format":  format,
					"output":  outFile,
					"entries": len(exchanges),
				}, func() {
					fmt.Printf("✓ Exported %d exchanges as %s → %s\n", len(exchanges), format, outFile)
				})
				return nil
			}

			if format == "csv" {
				fmt.Print(data.(string))
			} else {
				output.PrintJSON(data)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "export format: json|har|csv")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().IntVar(&limit, "limit", 0, "max exchanges to export (0 = all)")
	return cmd
}

func buildJSONExport(exchanges []historyExchange) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(exchanges))
	for _, e := range exchanges {
		entry := map[string]interface{}{
			"request_id":       e.ReqID,
			"method":           e.Method,
			"url":              e.URL,
			"request_headers":  parseHeaderJSON(e.ReqHeaders),
			"request_body":     string(e.ReqBody),
			"response_id":      e.RespID,
			"status_code":      e.Status,
			"reason":           e.Reason,
			"response_headers": parseHeaderJSON(e.RespHeaders),
			"response_body":    string(e.RespBody),
			"content_type":     e.ContentType,
			"length_bytes":     e.Length,
			"time_ms":          e.TimeMs,
			"source":           e.Source,
			"created_at":       e.CreatedAt,
		}
		out = append(out, entry)
	}
	return out
}

func buildHARExport(exchanges []historyExchange) map[string]interface{} {
	entries := make([]interface{}, 0, len(exchanges))
	for _, e := range exchanges {
		reqHeaders := make([]map[string]string, 0)
		for _, h := range parseHeaderJSON(e.ReqHeaders) {
			reqHeaders = append(reqHeaders, map[string]string{"name": h.Name, "value": h.Value})
		}
		reqCookies := make([]map[string]string, 0)
		for _, c := range parseCookieHeader(findHeader(e.ReqHeaders, "Cookie")) {
			reqCookies = append(reqCookies, map[string]string{"name": c.Name, "value": c.Value})
		}

		respHeaders := make([]map[string]string, 0)
		for _, h := range parseHeaderJSON(e.RespHeaders) {
			respHeaders = append(respHeaders, map[string]string{"name": h.Name, "value": h.Value})
		}
		respCookies := make([]map[string]interface{}, 0)
		for _, sc := range findHeaderValues(e.RespHeaders, "Set-Cookie") {
			respCookies = append(respCookies, map[string]interface{}{"name": sc, "value": ""})
		}

		request := map[string]interface{}{
			"method":      e.Method,
			"url":         e.URL,
			"httpVersion": "HTTP/1.1",
			"cookies":     reqCookies,
			"headers":     reqHeaders,
			"queryString": queryParams(e.URL),
			"headersSize": -1,
			"bodySize":    len(e.ReqBody),
		}
		if len(e.ReqBody) > 0 {
			request["postData"] = map[string]interface{}{
				"mimeType": findHeader(e.ReqHeaders, "Content-Type"),
				"text":     string(e.ReqBody),
			}
		}

		response := map[string]interface{}{
			"status":      e.Status,
			"statusText":  e.Reason,
			"httpVersion": "HTTP/1.1",
			"cookies":     respCookies,
			"headers":     respHeaders,
			"content": map[string]interface{}{
				"size":     e.Length,
				"mimeType": e.ContentType,
				"text":     string(e.RespBody),
			},
			"redirectURL": "",
			"headersSize": -1,
			"bodySize":    e.Length,
		}

		entries = append(entries, map[string]interface{}{
			"startedDateTime": e.CreatedAt,
			"time":            e.TimeMs,
			"request":         request,
			"response":        response,
			"cache":           map[string]interface{}{},
			"timings": map[string]interface{}{
				"send":    0,
				"wait":    e.TimeMs,
				"receive": 0,
			},
			"_agentburp_request_id": e.ReqID,
			"_agentburp_source":     e.Source,
		})
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"version": "1.2",
			"creator": map[string]interface{}{
				"name":    "AgentBurp",
				"version": "0.1.0",
			},
			"entries": entries,
		},
	}
}

func buildCSVExport(exchanges []historyExchange) string {
	var b strings.Builder
	b.WriteString("request_id,method,url,status_code,content_type,length_bytes,time_ms,source,created_at\n")
	for _, e := range exchanges {
		fmt.Fprintf(&b, "%s,%s,%s,%d,%s,%d,%d,%s,%s\n",
			escapeCSV(e.ReqID), escapeCSV(e.Method), escapeCSV(e.URL),
			e.Status, escapeCSV(e.ContentType), e.Length, e.TimeMs,
			escapeCSV(e.Source), escapeCSV(e.CreatedAt))
	}
	return b.String()
}

func escapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func parseHeaderJSON(j string) []models.Header {
	var hs []models.Header
	json.Unmarshal([]byte(j), &hs)
	return hs
}

func findHeader(headersJSON, name string) string {
	for _, h := range parseHeaderJSON(headersJSON) {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func findHeaderValues(headersJSON, name string) []string {
	var out []string
	for _, h := range parseHeaderJSON(headersJSON) {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

func parseCookieHeader(header string) []models.CookieEntry {
	var out []models.CookieEntry
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			out = append(out, models.CookieEntry{Name: kv[0], Value: kv[1]})
		}
	}
	return out
}

func queryParams(rawURL string) []map[string]string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var out []map[string]string
	for k, vals := range u.Query() {
		for _, v := range vals {
			out = append(out, map[string]string{"name": k, "value": v})
		}
	}
	return out
}

type historyExchange struct {
	ReqID       string
	Method      string
	URL         string
	ReqHeaders  string
	ReqBody     []byte
	RespID      string
	Status      int
	Reason      string
	RespHeaders string
	RespBody    []byte
	ContentType string
	Length      int
	TimeMs      int64
	Source      string
	CreatedAt   string
}

func openProjectDB(projectName string) (*core.DB, error) {
	dbPath := core.ProjectDBPath(projectName)
	db, err := core.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open project %q: %w", projectName, err)
	}
	return db, nil
}

func fetchRequest(db *sql.DB, reqID string, headN int, bodyFull bool) (*models.Request, error) {
	row := db.QueryRow(`
		SELECT id, project_id, source, method, url, host, port, scheme, path,
		       query_string, headers_json, body_blob, body_hash, LENGTH(COALESCE(body_blob,'')),
		       COALESCE(session_id,''), COALESCE(endpoint_id,''), created_at, note
		FROM requests WHERE id = ?`, reqID)

	var r models.Request
	var headersJSON string
	var bodyBlob []byte
	if err := row.Scan(
		&r.ID, &r.ProjectID, &r.Source, &r.Method, &r.URL, &r.Host,
		&r.Port, &r.Scheme, &r.Path, &r.QueryString,
		&headersJSON, &bodyBlob, &r.BodyHash, &r.BodySize,
		&r.SessionID, &r.EndpointID, &r.CreatedAt, &r.Note,
	); err != nil {
		return nil, fmt.Errorf("request %q not found: %w", reqID, err)
	}
	json.Unmarshal([]byte(headersJSON), &r.Headers)

	if bodyFull && len(bodyBlob) > 0 {
		if len(bodyBlob) > 102400 {
			fmt.Printf("⚠ Body is %s — returning anyway (--head N for partial)\n", humanBytes(len(bodyBlob)))
		}
		r.Body = bodyBlob
	} else if headN > 0 && len(bodyBlob) > 0 {
		truncated, wasTruncated := output.TruncateBody(bodyBlob, headN)
		r.Body = truncated
		r.Truncated = wasTruncated
	}
	return &r, nil
}

func fetchResponse(db *sql.DB, reqID string, headN int, bodyFull bool) (*models.Response, error) {
	row := db.QueryRow(`
		SELECT id, request_id, status_code, reason, headers_json, body_blob,
		       body_hash, content_type, length_bytes, time_ms, redirect_chain_json, created_at
		FROM responses WHERE request_id = ? ORDER BY created_at DESC LIMIT 1`, reqID)

	var r models.Response
	var headersJSON, redirectJSON string
	var bodyBlob []byte
	if err := row.Scan(
		&r.ID, &r.RequestID, &r.StatusCode, &r.Reason, &headersJSON, &bodyBlob,
		&r.BodyHash, &r.ContentType, &r.BodySize, &r.TimeMs, &redirectJSON, &r.CreatedAt,
	); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(headersJSON), &r.Headers)
	json.Unmarshal([]byte(redirectJSON), &r.RedirectChain)

	if bodyFull && len(bodyBlob) > 0 {
		r.Body = bodyBlob
	} else if headN > 0 && len(bodyBlob) > 0 {
		truncated, wasTruncated := output.TruncateBody(bodyBlob, headN)
		r.Body = truncated
		r.Truncated = wasTruncated
	}
	return &r, nil
}

func printRequestHuman(r *models.Request, view string) {
	fmt.Printf("━━━ REQUEST ━━━ %s\n", r.ID)
	fmt.Printf("%s %s HTTP/1.1\n", r.Method, r.URL)
	for _, h := range r.Headers {
		fmt.Printf("%s: %s\n", h.Name, h.Value)
	}
	if len(r.Body) > 0 {
		fmt.Printf("\n%s", r.Body)
		if r.Truncated {
			fmt.Printf("\n... [truncated — %s total]\n", humanBytes(r.BodySize))
		}
	} else if r.BodySize > 0 {
		fmt.Printf("\n[body: %s — use --head N or --body-only to read]\n", humanBytes(r.BodySize))
	}
	fmt.Println()
}

func printResponseHuman(r *models.Response, view string) {
	fmt.Printf("━━━ RESPONSE ━━━ %s (%dms)\n", r.ID, r.TimeMs)
	fmt.Printf("HTTP/1.1 %d %s\n", r.StatusCode, r.Reason)
	for _, h := range r.Headers {
		fmt.Printf("%s: %s\n", h.Name, h.Value)
	}
	if len(r.Body) > 0 {
		fmt.Printf("\n%s", r.Body)
		if r.Truncated {
			fmt.Printf("\n... [truncated — %s total]\n", humanBytes(r.BodySize))
		}
	} else if r.BodySize > 0 {
		fmt.Printf("\n[body: %s — use --head N or --body-only to read]\n", humanBytes(r.BodySize))
	}
	fmt.Println()
}

func humanBytes(n int) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/1024/1024)
	case n >= 1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

var _ = strings.Contains
