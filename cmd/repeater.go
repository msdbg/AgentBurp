package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/adaptation"
	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/scope"
	"github.com/msdbg/AgentBurp/internal/transport"
	"github.com/spf13/cobra"
)

func hashBodyBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newRepeaterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repeater",
		Short: "Clone, edit, and replay HTTP requests",
		Long: `The repeater lets you modify and resend captured requests.

Workflow:
  1. Clone a captured request:        agentburp repeater clone <req_id>
  2. Edit the clone:                  agentburp repeater edit <rreq_id> --header "X-Test: 1"
  3. Send it:                         agentburp repeater send <rreq_id>
  4. Compare with original:           agentburp repeater compare <req_id> <rreq_id>`,
	}
	cmd.AddCommand(
		repeaterCloneCmd(),
		repeaterEditCmd(),
		repeaterSendCmd(),
		repeaterComposeCmd(),
		repeaterCompareCmd(),
	)
	return cmd
}

func repeaterCloneCmd() *cobra.Command {
	var label string
	cmd := &cobra.Command{
		Use:   "clone <req_id>",
		Short: "Clone a captured request for editing",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp repeater clone req_abc123
  agentburp repeater clone req_abc123 --label "test-admin-bypass" --json`,
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

			req, err := fetchRequest(db.Conn(), args[0], 0, true)
			if err != nil {
				return err
			}

			cloneID := core.NewID("rreq")
			now := core.TimestampNow()
			headersJSON, _ := json.Marshal(req.Headers)
			if label == "" {
				label = fmt.Sprintf("clone of %s", core.ShortID(args[0]))
			}
			_, err = db.Conn().Exec(`
				INSERT INTO repeater_requests
				  (id, project_id, parent_req_id, method, url, headers_json, body_blob, label, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				cloneID, proj.ID, args[0],
				req.Method, req.URL, string(headersJSON), req.Body,
				label, now, now,
			)
			if err != nil {
				return fmt.Errorf("clone request: %w", err)
			}

			result := map[string]string{
				"id":         cloneID,
				"parent_id":  args[0],
				"label":      label,
				"created_at": now,
			}
			output.PrintAuto(result, func() {
				fmt.Printf("✓ Request cloned: %s\n", cloneID)
				fmt.Printf("  Parent: %s\n", args[0])
				fmt.Printf("  Label:  %s\n\n", label)
				fmt.Printf("Next:\n")
				fmt.Printf("  agentburp repeater edit %s --header \"X-Custom: value\"\n", cloneID)
				fmt.Printf("  agentburp repeater send %s\n", cloneID)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "label for this repeater request")
	return cmd
}

func repeaterEditCmd() *cobra.Command {
	var (
		setHeaders []string
		setParam   []string
		setBody    string
		setMethod  string
		setURL     string
	)
	cmd := &cobra.Command{
		Use:   "edit <rreq_id>",
		Short: "Edit a repeater request",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp repeater edit rreq_abc123 --header "X-Admin: true"
  agentburp repeater edit rreq_abc123 --method PUT --body '{"role":"admin"}'
  agentburp repeater edit rreq_abc123 --param "id=999"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			rreqID := args[0]

			row := db.Conn().QueryRow(`SELECT method, url, headers_json, body_blob FROM repeater_requests WHERE id = ?`, rreqID)
			var method, rawURL, headersJSON string
			var body []byte
			if err := row.Scan(&method, &rawURL, &headersJSON, &body); err != nil {
				return fmt.Errorf("repeater request %q not found", rreqID)
			}

			var headers []models.Header
			json.Unmarshal([]byte(headersJSON), &headers)

			if setMethod != "" {
				method = strings.ToUpper(setMethod)
			}
			if setURL != "" {
				rawURL = setURL
			}
			if setBody != "" {
				body = []byte(setBody)
			}

			for _, h := range setHeaders {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid header format %q — use 'Name: Value'", h)
				}
				name := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				updated := false
				for i, existing := range headers {
					if strings.EqualFold(existing.Name, name) {
						headers[i].Value = val
						updated = true
						break
					}
				}
				if !updated {
					headers = append(headers, models.Header{Name: name, Value: val})
				}
			}

			if len(setParam) > 0 {
				u, err := url.Parse(rawURL)
				if err != nil {
					return err
				}
				q := u.Query()
				for _, p := range setParam {
					parts := strings.SplitN(p, "=", 2)
					if len(parts) == 2 {
						q.Set(parts[0], parts[1])
					}
				}
				u.RawQuery = q.Encode()
				rawURL = u.String()
			}

			newHeadersJSON, _ := json.Marshal(headers)
			now := core.TimestampNow()
			_, err = db.Conn().Exec(`
				UPDATE repeater_requests
				SET method = ?, url = ?, headers_json = ?, body_blob = ?, updated_at = ?
				WHERE id = ?`,
				method, rawURL, string(newHeadersJSON), body, now, rreqID,
			)
			if err != nil {
				return err
			}

			output.PrintAuto(map[string]interface{}{
				"id":         rreqID,
				"method":     method,
				"url":        rawURL,
				"updated_at": now,
			}, func() {
				fmt.Printf("✓ Repeater request updated: %s\n", rreqID)
				fmt.Printf("  %s %s\n", method, rawURL)
			})
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&setHeaders, "header", "H", nil, "set header (format: 'Name: Value', repeatable)")
	cmd.Flags().StringArrayVar(&setParam, "param", nil, "set query param (format: 'key=value')")
	cmd.Flags().StringVar(&setBody, "body", "", "set request body")
	cmd.Flags().StringVar(&setMethod, "method", "", "set HTTP method")
	cmd.Flags().StringVar(&setURL, "url", "", "set URL")
	return cmd
}

func repeaterSendCmd() *cobra.Command {
	var (
		followRedirects bool
		sessionID       string
		noSession       bool
		timeout         int
		transportName   string
	)
	cmd := &cobra.Command{
		Use:   "send <rreq_id>",
		Short: "Send a repeater request",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp repeater send rreq_abc123 --json
  agentburp repeater send rreq_abc123 --follow-redirects
  agentburp repeater send rreq_abc123 --no-session
  agentburp repeater send rreq_abc123 --dry-run`,
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

			rreqID := args[0]
			row := db.Conn().QueryRow(`SELECT method, url, headers_json, body_blob FROM repeater_requests WHERE id = ?`, rreqID)
			var method, rawURL, headersJSON string
			var body []byte
			if err := row.Scan(&method, &rawURL, &headersJSON, &body); err != nil {
				return fmt.Errorf("repeater request %q not found", rreqID)
			}
			var headers []models.Header
			json.Unmarshal([]byte(headersJSON), &headers)

			var session *models.Session
			sessID := sessionID
			if noSession {
				sessID = ""
			}
			hasManualCookie := false
			if sessID == "" {
				for _, h := range headers {
					if strings.EqualFold(h.Name, "Cookie") {
						hasManualCookie = true
						break
					}
				}
			}
			if sessID == "" && !noSession {
				sessID = auth.ActiveSessionID(projectName)
			}
			if sessID != "" && !(hasManualCookie && sessionID == "") {
				store := auth.NewSessionStore(db, proj.ID)
				session, err = store.Get(sessID)
				if err != nil {
					return fmt.Errorf("session %q: %w — use: agentburp auth session list", sessID, err)
				}
				headers = store.ApplyToRequest(session, headers)
			}

			var transportProfile string
			if transportName != "" {

				if _, ok := transport.ValidTypes[transport.Type(transportName)]; !ok {
					store := transport.NewStore(db, proj.ID)
					if _, err := store.GetByName(transportName); err != nil {
						if _, err2 := store.GetByID(transportName); err2 != nil {
							return fmt.Errorf("unknown transport %q — valid types: raw-http, fast-http, browser-session, browser-fetch, external-transport (or create profile via: agentburp transport create --name <n> --type <t>)", transportName)
						}
					}
				}
				transportProfile = transportName

				db.Conn().Exec(`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					core.NewID("evt"), proj.ID, core.TimestampNow(), "agent", "transport.use", "transport", transportProfile, "ok", fmt.Sprintf(`{"transport":%q,"request":%q}`, transportProfile, rreqID))
			}

			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"would_send": 1,
					"method":     method,
					"url":        rawURL,
					"headers":    len(headers),
					"body_bytes": len(body),
					"session":    sessID,
					"transport":  transportProfile,
				})
				return nil
			}

			scopeEngine, err := scope.NewEngine(db, proj.ID)
			if err != nil {
				return err
			}
			if !scopeEngine.IsInScope(rawURL) {
				result := scopeEngine.Check(rawURL)
				auditLog := scope.NewAuditLogger(db, proj.ID)
				auditLog.LogScopeViolation(rawURL, result.Reason)
				return fmt.Errorf("scope violation: %s is out of scope (%s)", rawURL, result.Reason)
			}

			var bodyReader io.Reader
			if len(body) > 0 {
				bodyReader = strings.NewReader(string(body))
			}
			httpReq, err := http.NewRequest(method, rawURL, bodyReader)
			if err != nil {
				return fmt.Errorf("build request: %w", err)
			}
			for _, h := range headers {
				httpReq.Header.Set(h.Name, h.Value)
			}

			jar, _ := cookiejar.New(nil)
			client := &http.Client{
				Jar:     jar,
				Timeout: time.Duration(timeout) * time.Second,
			}
			var redirectChain []string
			var redirectSetCookies []string
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				redirectChain = append(redirectChain, req.URL.String())

				if req.Response != nil {
					redirectSetCookies = append(redirectSetCookies, req.Response.Header.Values("Set-Cookie")...)
				}
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				if !followRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			}

			start := time.Now()
			resp, err := client.Do(httpReq)
			if err != nil {
				return fmt.Errorf("send request: %w", err)
			}
			defer resp.Body.Close()
			elapsed := time.Since(start).Milliseconds()

			respBody, _ := io.ReadAll(resp.Body)

			reqID := core.NewID("req")
			respID := core.NewID("resp")
			now := core.TimestampNow()
			reqHeadersJSON, _ := json.Marshal(headers)
			path := httpReq.URL.Path
			if path == "" {
				path = "/"
			}
			portNum := 80
			if httpReq.URL.Port() != "" {
				portNum, _ = strconv.Atoi(httpReq.URL.Port())
			} else if httpReq.URL.Scheme == "https" {
				portNum = 443
			}
			reqBodyHash := ""
			if len(body) > 0 {
				reqBodyHash = hashBodyBytes(body)
			}
			db.Conn().Exec(`
				INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
					query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
				VALUES (?, ?, 'repeater', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				reqID, proj.ID, method, rawURL,
				httpReq.URL.Hostname(), portNum, httpReq.URL.Scheme, path,
				httpReq.URL.RawQuery, string(reqHeadersJSON), body, reqBodyHash,
				sessID, rreqID, now,
			)

			var respHeaders []models.Header
			for _, v := range redirectSetCookies {
				respHeaders = append(respHeaders, models.Header{Name: "Set-Cookie", Value: v})
			}
			for k, vals := range resp.Header {
				for _, v := range vals {
					respHeaders = append(respHeaders, models.Header{Name: k, Value: v})
				}
			}
			respHeadersJSON, _ := json.Marshal(respHeaders)
			ct := resp.Header.Get("Content-Type")
			if idx := strings.IndexByte(ct, ';'); idx != -1 {
				ct = strings.TrimSpace(ct[:idx])
			}
			redirectJSON, _ := json.Marshal(redirectChain)
			db.Conn().Exec(`
				INSERT INTO responses (id, request_id, status_code, reason, headers_json, body_blob,
					body_hash, content_type, length_bytes, time_ms, redirect_chain_json, created_at)
				VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)`,
				respID, reqID, resp.StatusCode,
				string(respHeadersJSON), respBody, hashBodyBytes(respBody),
				ct, len(respBody), elapsed, string(redirectJSON), now,
			)

			context.ExtractEndpoint(db.Conn(), proj.ID, reqID, httpReq.URL.Hostname(), method, path, httpReq.URL.RawQuery, httpReq.Header, body)
			context.UpdateEndpointResponse(db.Conn(), reqID, resp.StatusCode, ct)
			auditLog := scope.NewAuditLogger(db, proj.ID)
			auditLog.LogRequestSent(reqID, "repeater")

			displayBody, truncated := output.TruncateBody(respBody, 4096)

			result := map[string]interface{}{
				"request_id":   reqID,
				"response_id":  respID,
				"status_code":  resp.StatusCode,
				"time_ms":      elapsed,
				"body_size":    len(respBody),
				"content_type": ct,
				"session_id":   sessID,
				"transport":    transportProfile,
				"redirects":    redirectChain,
				"truncated":    truncated,
				"body_preview": string(displayBody),
			}

			{
				hdrMap := map[string][]string{}
				for _, h := range respHeaders {
					hdrMap[h.Name] = append(hdrMap[h.Name], h.Value)
				}
				if dt, reason := adaptation.Classify(resp.StatusCode, hdrMap, string(respBody)); dt != "" {
					eng := adaptation.NewEngine(db, proj.ID)
					det, _ := eng.RecordDetection(reqID, respID, dt, "medium", map[string]interface{}{
						"status":    resp.StatusCode,
						"reason":    reason,
						"transport": transportProfile,
						"url":       rawURL,
						"action":    adaptation.RecommendedAction(dt),
					})
					if det != nil {

						eng.RecordAdaptation(det.ID, string(adaptation.RecommendedAction(dt)), "pending", map[string]interface{}{
							"transport": transportProfile,
							"status":    resp.StatusCode,
						})
						result["detection"] = dt
						result["detection_reason"] = reason
						result["recommended_action"] = adaptation.RecommendedAction(dt)
					}
				}

				detail := map[string]interface{}{
					"transport":    transportProfile,
					"session":      sessID,
					"status":       resp.StatusCode,
					"content_type": ct,
				}
				db.Conn().Exec(`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					core.NewID("evt"), proj.ID, core.TimestampNow(), "agent", "request.send", "request", reqID, "ok", fmt.Sprintf(`{"transport":%q,"status":%d}`, transportProfile, resp.StatusCode))
				_ = detail
			}
			output.PrintAuto(result, func() {
				fmt.Printf("HTTP %d %s (%dms, %s)\n",
					resp.StatusCode, resp.Status, elapsed, humanBytes(len(respBody)))
				fmt.Printf("Request saved: %s | Response saved: %s\n\n", reqID, respID)
				if len(redirectChain) > 0 {
					fmt.Printf("Redirects (%d):\n", len(redirectChain))
					for _, r := range redirectChain {
						fmt.Printf("  → %s\n", r)
					}
					fmt.Println()
				}
				if len(displayBody) > 0 {
					fmt.Printf("Body preview (first %s):\n%s\n", humanBytes(len(displayBody)), displayBody)
					if truncated {
						fmt.Printf("... [truncated]\n")
					}
				}
			})
			return nil
		},
	}
	cmd.Flags().BoolVar(&followRedirects, "follow-redirects", true, "follow HTTP redirects")
	cmd.Flags().StringVar(&sessionID, "session", "", "session ID to use for auth headers/cookies")
	cmd.Flags().BoolVar(&noSession, "no-session", false, "do not apply any session credentials")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "request timeout in seconds")
	cmd.Flags().StringVar(&transportName, "transport", "", "transport profile name or type (raw-http, browser-session, browser-fetch, fast-http, external-transport)")
	return cmd
}

func repeaterComposeCmd() *cobra.Command {
	var (
		method  string
		rawURL  string
		headers []string
		body    string
	)
	cmd := &cobra.Command{
		Use:   "compose",
		Short: "Build a new request from scratch",
		Example: `  agentburp repeater compose --method POST --url https://api.example.com/login \
    --header "Content-Type: application/json" \
    --body '{"username":"admin","password":"test"}'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if method == "" || rawURL == "" {
				return fmt.Errorf("--method and --url are required")
			}
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

			var parsedHeaders []models.Header
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					parsedHeaders = append(parsedHeaders, models.Header{
						Name:  strings.TrimSpace(parts[0]),
						Value: strings.TrimSpace(parts[1]),
					})
				}
			}
			headersJSON, _ := json.Marshal(parsedHeaders)
			id := core.NewID("rreq")
			now := core.TimestampNow()
			db.Conn().Exec(`
				INSERT INTO repeater_requests (id, project_id, method, url, headers_json, body_blob, label, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, 'composed', ?, ?)`,
				id, proj.ID, strings.ToUpper(method), rawURL, string(headersJSON), []byte(body), now, now,
			)

			output.PrintAuto(map[string]string{"id": id, "method": method, "url": rawURL}, func() {
				fmt.Printf("✓ Composed request: %s\n", id)
				fmt.Printf("  %s %s\n", strings.ToUpper(method), rawURL)
				fmt.Printf("\nSend it: agentburp repeater send %s\n", id)
			})
			return nil
		},
	}
	cmd.Flags().StringVarP(&method, "method", "m", "", "HTTP method (required)")
	cmd.Flags().StringVarP(&rawURL, "url", "u", "", "target URL (required)")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "header in 'Name: Value' format")
	cmd.Flags().StringVar(&body, "body", "", "request body")
	return cmd
}

func repeaterCompareCmd() *cobra.Command {
	var field string
	cmd := &cobra.Command{
		Use:   "compare <req_id_a> <req_id_b>",
		Short: "Compare two requests or responses",
		Args:  cobra.ExactArgs(2),
		Example: `  agentburp repeater compare req_abc123 rreq_def456
  agentburp repeater compare req_abc123 rreq_def456 --field response --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			kind := "response"
			switch field {
			case "request":
				kind = "request"
			case "response":
				kind = "response"
			case "both":

				if d, err := diffObjects(db.Conn(), args[0], args[1], "request"); err == nil {
					output.PrintAuto(d, func() { printDiffHuman(d) })
					fmt.Println()
				}
				d, err := diffObjects(db.Conn(), args[0], args[1], "response")
				if err != nil {
					return err
				}
				output.PrintAuto(d, func() { printDiffHuman(d) })
				return nil
			default:
				return fmt.Errorf("invalid --field %q — use request|response|both", field)
			}

			d, err := diffObjects(db.Conn(), args[0], args[1], kind)
			if err != nil {
				return err
			}
			output.PrintAuto(d, func() { printDiffHuman(d) })
			return nil
		},
	}
	cmd.Flags().StringVar(&field, "field", "response", "what to compare: request|response|both")
	return cmd
}
