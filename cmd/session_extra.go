package cmd

import (
	"fmt"
	"net/http"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newSessionValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Session utilities (validate, use, list) — alias for auth session + validate",
		Long: `Session commands for browser-to-HTTP handoff validation.

Examples:
  agentburp session use <sess_id> --json
  agentburp session validate <sess_id> --url https://app.example.com/dashboard --json
  agentburp session list --json`,
	}
	cmd.AddCommand(
		sessionValidateCmd(),
		sessionUseAliasCmd(),
		sessionListAliasCmd(),
	)
	return cmd
}

func sessionValidateCmd() *cobra.Command {
	var targetURL string
	cmd := &cobra.Command{
		Use:     "validate <session_id>",
		Short:   "Validate a session by sending a request to a URL",
		Args:    cobra.ExactArgs(1),
		Example: `  agentburp session validate sess_abc123 --url https://app.example.com/dashboard --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetURL == "" {
				return fmt.Errorf("--url is required")
			}
			sessID := args[0]
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
			store := auth.NewSessionStore(db, proj.ID)
			sess, err := store.Get(sessID)
			if err != nil {
				return err
			}

			headers := store.ApplyToRequest(sess, nil)
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return err
			}
			for _, h := range headers {
				req.Header.Set(h.Name, h.Value)
			}
			client := &http.Client{Timeout: 15 * time.Second}
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("validate request failed: %w", err)
			}
			defer resp.Body.Close()
			elapsed := time.Since(start).Milliseconds()
			result := map[string]interface{}{
				"session_id":  sessID,
				"url":         targetURL,
				"status_code": resp.StatusCode,
				"time_ms":     elapsed,
				"valid":       resp.StatusCode < 400,
				"headers":     headers,
			}
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				result["valid"] = false
				result["reason"] = "session rejected (401/403) — may need refresh via auth macro"
				result["suggested_action"] = "agentburp auth macro run <macro> or agentburp browser open --headed --wait-for-human"
			}
			output.PrintAuto(result, func() {
				if resp.StatusCode < 400 {
					fmt.Printf("✓ Session %s valid: %s -> HTTP %d (%dms)\n", core.ShortID(sessID), targetURL, resp.StatusCode, elapsed)
				} else {
					fmt.Printf("✗ Session %s invalid: %s -> HTTP %d\n", core.ShortID(sessID), targetURL, resp.StatusCode)
					fmt.Printf("  Suggestion: rerun auth macro or browser login\n")
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&targetURL, "url", "", "URL to validate session against (required)")
	return cmd
}

func sessionUseAliasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <sess_id>",
		Short: "Set active session (alias for auth session use)",
		Args:  cobra.ExactArgs(1),
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
			store := auth.NewSessionStore(db, proj.ID)
			if _, err := store.Get(args[0]); err != nil {
				return fmt.Errorf("session %q not found", args[0])
			}
			if err := auth.SetActiveSession(projectName, args[0]); err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"session_id": args[0], "status": "active"}, func() {
				fmt.Printf("✓ Active session: %s\n", args[0])
			})
			return nil
		},
	}
}

func sessionListAliasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List sessions (alias for auth session list)",
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
			rows, err := db.Conn().Query(`SELECT id, name, role, created_at FROM sessions WHERE project_id = ? ORDER BY created_at DESC`, proj.ID)
			if err != nil {
				return err
			}
			defer rows.Close()
			type S struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Role      string `json:"role"`
				CreatedAt string `json:"created_at"`
			}
			var list []S
			for rows.Next() {
				var s S
				rows.Scan(&s.ID, &s.Name, &s.Role, &s.CreatedAt)
				list = append(list, s)
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No sessions.")
					return
				}
				for _, s := range list {
					fmt.Printf("  %s  %s  %s\n", core.ShortID(s.ID), s.Name, s.CreatedAt)
				}
			})
			return nil
		},
	}
}

func newRequestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request utilities (alias for repeater)",
	}
	cmd.AddCommand(
		requestSendCmd(),
		requestEditCmd(),
	)
	return cmd
}

func requestSendCmd() *cobra.Command {
	var (
		transportName string
		sessionID     string
	)
	cmd := &cobra.Command{
		Use:   "send <req_id|rreq_id>",
		Short: "Send a request (repeater) via selected transport",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp request send req_abc123 --transport browser-session --json
  agentburp request send rreq_abc123 --transport raw-http --session sess_abc123 --json`,
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

			if transportName != "" {

				db.Conn().Exec(`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					core.NewID("evt"), proj.ID, core.TimestampNow(), "agent", "request.send", "transport", transportName, "ok", fmt.Sprintf(`{"transport":%q,"request":%q}`, transportName, args[0]))
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{"request": args[0], "transport": transportName, "session": sessionID})
				return nil
			}

			rreqID := args[0]

			var exists int
			db.Conn().QueryRow(`SELECT 1 FROM repeater_requests WHERE id = ?`, rreqID).Scan(&exists)
			if exists != 1 {

				var method, urlStr, headersJSON string
				var body []byte
				err := db.Conn().QueryRow(`SELECT method, url, headers_json, body_blob FROM requests WHERE id = ?`, rreqID).Scan(&method, &urlStr, &headersJSON, &body)
				if err != nil {
					return fmt.Errorf("request %q not found (neither repeater nor history)", rreqID)
				}

				rreqID = core.NewID("rreq")
				now := core.TimestampNow()
				db.Conn().Exec(`INSERT INTO repeater_requests (id, project_id, parent_req_id, method, url, headers_json, body_blob, label, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					rreqID, proj.ID, args[0], method, urlStr, headersJSON, body, "request-send:"+args[0], now, now)
			}

			output.PrintAuto(map[string]interface{}{
				"request_id": rreqID,
				"transport":  transportName,
				"note":       "Delegated to repeater. Use: agentburp repeater send " + rreqID + " --transport " + transportName,
			}, func() {
				fmt.Printf("Request %s prepared as %s (transport: %s)\n", args[0], rreqID, transportName)
				fmt.Printf("Send via: agentburp repeater send %s --transport %s --json\n", rreqID, transportName)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&transportName, "transport", "", "transport profile name or type (raw-http, browser-session, etc.)")
	cmd.Flags().StringVar(&sessionID, "session", "", "session ID")
	return cmd
}

func requestEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit <req_id>",
		Short: "Edit a request (alias for repeater edit)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("use: agentburp repeater edit %s --header \"Name: Value\" --body '...' — request edit is an alias for repeater edit", args[0])
		},
	}
}
