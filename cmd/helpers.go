package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/crawler"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/scanner"
	"github.com/msdbg/AgentBurp/internal/scope"
	"github.com/spf13/cobra"
)

// Shared helpers used across multiple command files

// getProject is a convenience wrapper for fetching the active project.
func getProject(db *core.DB, projectName string) (*core.Project, error) {
	return core.NewProjectStore(db).Get(projectName)
}

// createJob inserts a new job record and returns its ID.
func createJob(db *sql.DB, projectID, jobType string, config map[string]interface{}) string {
	id := core.NewID("job")
	now := core.TimestampNow()
	configJSON, _ := json.Marshal(config)
	db.Exec(`
		INSERT INTO jobs (id, project_id, type, status, config_json, created_at)
		VALUES (?, ?, ?, 'queued', ?, ?)`,
		id, projectID, jobType, string(configJSON), now,
	)
	return id
}

func newCrawlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crawl",
		Short: "Web crawler and spider (content discovery)",
		Long: `The crawler discovers application content by following links, forms,
and JavaScript-generated requests.

Two modes:
  static   — parse HTML links, forms, JS endpoints (fast, no browser)
  headless — use headless Chrome via go-rod (for SPAs and JS-heavy apps)

The crawler respects scope rules. Out-of-scope URLs are never followed.`,
	}
	cmd.AddCommand(crawlStartCmd(), crawlStopCmd(), crawlStatusCmd(), crawlResultsCmd())
	return cmd
}

func crawlStartCmd() *cobra.Command {
	var (
		maxDepth    int
		headless    bool
		scopePolicy string
		sessionID   string
		rateLimit   int
		concurrency int
		maxPages    int
		proxyURL    string
	)
	cmd := &cobra.Command{
		Use:   "start <url>",
		Short: "Start a crawl",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp crawl start https://app.example.com --dry-run
  agentburp crawl start https://app.example.com --max-depth 5 --headless
  agentburp crawl start https://app.example.com --session sess_admin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
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
			cfg, err := core.LoadConfig(projectName)
			if err != nil {
				return err
			}
			if rateLimit <= 0 {
				rateLimit = cfg.RateLimitPerHost
			}

			opts := crawler.Options{
				Target:      targetURL,
				MaxDepth:    maxDepth,
				Headless:    headless,
				SessionID:   sessionID,
				Rate:        rateLimit,
				Concurrency: concurrency,
				MaxPages:    maxPages,
				ProxyURL:    proxyURL,
			}

			// Resolve session headers.
			var session []models.Header
			if sessionID == "" {
				sessionID = auth.ActiveSessionID(projectName)
			}
			if sessionID != "" {
				s, err := auth.NewSessionStore(db, proj.ID).Get(sessionID)
				if err == nil {
					session = auth.NewSessionStore(db, proj.ID).ApplyToRequest(s, nil)
				}
			}

			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"target":       targetURL,
					"max_depth":    maxDepth,
					"headless":     headless,
					"scope_policy": scopePolicy,
					"session":      sessionID,
					"rate_limit":   rateLimit,
					"max_pages":    maxPages,
					"proxy":        proxyURL,
					"note":         "Crawl would discover all reachable URLs within scope",
				})
				return nil
			}

			jobID, err := core.NewJobStore(db).Create(proj.ID, "crawl", map[string]interface{}{
				"target":       targetURL,
				"max_depth":    maxDepth,
				"headless":     headless,
				"scope_policy": scopePolicy,
				"session_id":   sessionID,
				"rate_limit":   rateLimit,
				"max_pages":    maxPages,
				"proxy":        proxyURL,
			})
			if err != nil {
				return err
			}

			runner, err := crawler.NewRunner(db, proj, jobID, opts, session)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				core.NewJobStore(db).SetStatus(jobID, "cancelled")
			}()

			fmt.Printf("Starting crawl of %s (depth: %d, rate: %d/s%s)...\n",
				targetURL, maxDepth, rateLimit, headlessSuffix(headless))
			start := time.Now()
			err = runner.Run(ctx)
			if err != nil {
				return err
			}
			job, _ := core.NewJobStore(db).Get(jobID)
			if job.Status == "cancelled" {
				fmt.Printf("Crawl job %s cancelled after %s\n", jobID, time.Since(start).Round(time.Second))
				return nil
			}
			fmt.Printf("✓ Crawl finished in %s\n", time.Since(start).Round(time.Second))
			fmt.Printf("  Pages: %v | Requests: %v | Forms: %v | URLs: %v | Endpoints: %v\n",
				job.ResultSummary["pages_fetched"], job.ResultSummary["requests_sent"],
				job.ResultSummary["forms_submitted"], job.ResultSummary["urls_discovered"],
				job.ResultSummary["endpoint_count"])
			fmt.Printf("\nDetails: agentburp crawl results %s\n", jobID)
			return nil
		},
	}
	cmd.Flags().IntVar(&maxDepth, "max-depth", 3, "maximum crawl depth")
	cmd.Flags().BoolVar(&headless, "headless", false, "use headless browser (go-rod) for JS-heavy apps")
	cmd.Flags().StringVar(&scopePolicy, "scope", "allowed", "scope policy: allowed|all")
	cmd.Flags().StringVar(&sessionID, "session", "", "session ID for authenticated crawling")
	cmd.Flags().IntVar(&rateLimit, "rate", 0, "max requests per second per host (default: project config)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "number of concurrent workers")
	cmd.Flags().IntVar(&maxPages, "max-pages", 200, "maximum pages to fetch")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "route headless browsing through proxy URL (e.g. http://127.0.0.1:8080)")
	return cmd
}

func modeSuffix(all bool) string {
	if all {
		return " on all captured traffic"
	}
	return ""
}

func headlessSuffix(headless bool) string {
	if headless {
		return ", headless Chrome"
	}
	return ""
}

func crawlStopCmd() *cobra.Command {
	return &cobra.Command{
		Use: "stop <job_id>", Short: "Stop a running crawl",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := core.NewJobStore(db).Cancel(args[0]); err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"job_id": args[0], "status": "cancelled"}, func() {
				fmt.Printf("✓ Crawl job %s cancelled\n", args[0])
			})
			return nil
		},
	}
}

func crawlStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status <job_id>", Short: "Check crawl job status",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			job, err := core.NewJobStore(db).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(job, func() {
				fmt.Printf("Job %s (%s): %s\n", job.ID, job.Type, job.Status)
				if job.Error != "" {
					fmt.Printf("  Error: %s\n", job.Error)
				}
				for k, v := range job.ResultSummary {
					if k != "discovered_urls" {
						fmt.Printf("  %s: %v\n", k, v)
					}
				}
			})
			return nil
		},
	}
}

func crawlResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "results <job_id>", Short: "Show crawl results",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			job, err := core.NewJobStore(db).Get(args[0])
			if err != nil {
				return err
			}
			urls, _ := job.ResultSummary["discovered_urls"].([]interface{})
			output.PrintAuto(map[string]interface{}{
				"job_id":    args[0],
				"status":    job.Status,
				"endpoints": job.ResultSummary["endpoint_count"],
				"urls":      urls,
			}, func() {
				fmt.Printf("Crawl results for job %s (status: %s):\n", args[0], job.Status)
				if len(urls) == 0 {
					fmt.Println("  (no URLs discovered)")
					return
				}
				for i, u := range urls {
					fmt.Printf("  %3d. %v\n", i+1, u)
				}
			})
			return nil
		},
	}
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication and session management",
		Long: `Manage authenticated testing sessions.

Auth profiles are YAML files that describe how to authenticate.
Supported types:
  json_login    — POST JSON credentials, capture token/cookies
  form_login    — submit HTML login form
  bearer        — static bearer token
  basic         — HTTP Basic auth
  header        — static custom headers

Example auth config (auth.yaml):
  name: admin_login
  type: json_login
  url: https://app.example.com/api/login
  method: POST
  body:
    username: ${USERNAME}
    password: ${PASSWORD}
  capture:
    cookies: true
    headers:
      - Authorization`,
	}
	cmd.AddCommand(
		authLoginCmd(),
		authSessionCmd(),
		authTokenCmd(),
		newAuthMacroCmd(),
	)
	return cmd
}

func authSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage authenticated sessions",
		Long: `Manage authenticated testing sessions.

Sessions hold cookies, headers, and tokens that are applied to
repeater, fuzzer, and crawler requests. One session can be marked
active per project with: agentburp auth session use <sess_id>`,
	}
	cmd.AddCommand(
		authSessionListCmd(),
		authSessionShowCmd(),
		authSessionUseCmd(),
		authSessionDeleteCmd(),
		authSessionCreateCmd(),
		authSessionIngestCmd(),
	)
	return cmd
}

func authLoginCmd() *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate using a profile config file",
		Example: `  agentburp auth login --config admin_login.yaml
  agentburp auth login --config admin_login.yaml --json
  agentburp auth login --config admin_login.yaml --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configFile == "" {
				return fmt.Errorf("--config is required")
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

			profile, err := auth.LoadProfile(configFile)
			if err != nil {
				return err
			}

			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"profile": profile.Name,
					"type":    profile.Type,
					"url":     profile.Substitute().URL,
					"capture": map[string]interface{}{
						"cookies": profile.Capture.Cookies,
						"headers": profile.Capture.Headers,
					},
					"note": "Would perform login and store cookies/tokens in a new session",
				})
				return nil
			}

			runner := auth.NewLoginRunner(db, proj.ID)
			result, err := runner.Login(projectName, profile)
			if err != nil {
				return err
			}

			auditLog := scope.NewAuditLogger(db, proj.ID)
			auditLog.Log("agent", "auth.login", "session", result.SessionID, "ok", map[string]interface{}{
				"profile": result.Profile,
				"status":  result.Status,
			})

			output.PrintAuto(result, func() {
				fmt.Printf("✓ Logged in: %s\n", result.SessionID)
				fmt.Printf("  Profile: %s (type: %s)\n", result.Profile, profile.Type)
				if result.Status != 0 {
					fmt.Printf("  Login response: HTTP %d (%dms)\n", result.Status, result.TimeMs)
				}
				if len(result.Cookies) > 0 {
					fmt.Printf("  Cookies: %d\n", len(result.Cookies))
					for _, c := range result.Cookies {
						fmt.Printf("    %s=%s\n", c.Name, c.Value)
					}
				}
				if len(result.Headers) > 0 {
					fmt.Printf("  Headers: %d\n", len(result.Headers))
					for _, h := range result.Headers {
						fmt.Printf("    %s: %s\n", h.Name, h.Value)
					}
				}
				if len(result.Tokens) > 0 {
					fmt.Printf("  Tokens: %d\n", len(result.Tokens))
					for k, v := range result.Tokens {
						fmt.Printf("    %s: %s\n", k, v)
					}
				}
				fmt.Printf("\nUse this session:\n")
				fmt.Printf("  agentburp auth session use %s\n", result.SessionID)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&configFile, "config", "", "auth profile YAML file (required)")
	return cmd
}

func authSessionListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List all sessions",
		Aliases: []string{"sessions"},
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
			rows, err := db.Conn().Query(
				`SELECT id, name, role, created_at FROM sessions WHERE project_id = ? ORDER BY created_at DESC`,
				proj.ID,
			)
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
			var sessions []S
			for rows.Next() {
				var s S
				rows.Scan(&s.ID, &s.Name, &s.Role, &s.CreatedAt)
				sessions = append(sessions, s)
			}
			output.PrintAuto(sessions, func() {
				if len(sessions) == 0 {
					fmt.Println("No sessions. Create one with: agentburp auth login --config <file>")
					return
				}
				output.PrintTable([]string{"ID", "NAME", "ROLE", "CREATED"},
					func() [][]string {
						var rows [][]string
						for _, s := range sessions {
							rows = append(rows, []string{core.ShortID(s.ID), s.Name, s.Role, s.CreatedAt})
						}
						return rows
					}())
			})
			return nil
		},
	}
}

func authSessionShowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "show <sess_id>", Short: "Show session details",
		Args:    cobra.ExactArgs(1),
		Example: `  agentburp auth session show sess_abc123 --json`,
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
			sess, err := store.Get(args[0])
			if err != nil {
				return err
			}

			output.PrintAuto(sess, func() {
				fmt.Printf("━━━ SESSION ━━━ %s\n", sess.ID)
				fmt.Printf("  Name:      %s\n", sess.Name)
				if sess.Role != "" {
					fmt.Printf("  Role:      %s\n", sess.Role)
				}
				if sess.AuthProfileID != "" {
					fmt.Printf("  Profile:   %s\n", sess.AuthProfileID)
				}
				fmt.Printf("  Created:   %s\n", sess.CreatedAt)
				if auth.ActiveSessionID(projectName) == sess.ID {
					fmt.Printf("  Status:    ACTIVE\n")
				}
				fmt.Printf("\nCookies (%d):\n", len(sess.Cookies))
				for _, c := range sess.Cookies {
					flags := ""
					if c.Secure {
						flags += " Secure"
					}
					if c.HttpOnly {
						flags += " HttpOnly"
					}
					fmt.Printf("  %s=%s%s\n", c.Name, c.Value, flags)
				}
				fmt.Printf("\nHeaders (%d):\n", len(sess.Headers))
				for _, h := range sess.Headers {
					fmt.Printf("  %s: %s\n", h.Name, h.Value)
				}
				fmt.Printf("\nTokens (%d):\n", len(sess.Tokens))
				for k, v := range sess.Tokens {
					fmt.Printf("  %s: %s\n", k, v)
				}
			})
			return nil
		},
	}
}

func authSessionUseCmd() *cobra.Command {
	return &cobra.Command{
		Use: "use <sess_id>", Short: "Set the active session for this project",
		Args: cobra.ExactArgs(1),
		Example: `  agentburp auth session use sess_abc123
  agentburp auth session use sess_abc123 --json`,
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
			// Validate the session exists
			store := auth.NewSessionStore(db, proj.ID)
			if _, err := store.Get(args[0]); err != nil {
				return fmt.Errorf("session %q not found — use: agentburp auth session list", args[0])
			}
			if err := auth.SetActiveSession(projectName, args[0]); err != nil {
				return err
			}
			output.PrintAuto(map[string]string{
				"session_id": args[0],
				"project":    projectName,
				"status":     "active",
			}, func() {
				fmt.Printf("✓ Active session set: %s\n", args[0])
				fmt.Printf("  Repeater/fuzzer/crawler requests will use this session's cookies, headers, and tokens.\n")
			})
			return nil
		},
	}
}

func authSessionDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use: "delete <sess_id>", Short: "Delete a session",
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
			store := auth.NewSessionStore(db, proj.ID)
			if err := store.Delete(args[0], projectName); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Session %s deleted", args[0]), nil)
			return nil
		},
	}
}

func authSessionIngestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ingest <sess_id> <req_id>",
		Short: "Capture cookies/tokens from a traffic exchange into a session",
		Long: `Pulls authentication material out of a captured request+response
into a session — the "cookie jar" workflow.

Captures:
  • Set-Cookie response headers → session cookie jar
  • Authorization / token headers from the request
  • token-like JSON fields in the response body (access_token, csrf_token, ...)`,
		Args: cobra.ExactArgs(2),
		Example: `  # create a session first
  agentburp auth session create admin --role admin
  # then ingest credentials from captured login traffic
  agentburp auth session ingest sess_abc123 req_xyz789 --json`,
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
			result, err := auth.CaptureFromTraffic(db.Conn(), proj.ID, args[0], args[1])
			if err != nil {
				return err
			}
			output.PrintAuto(result, func() {
				fmt.Printf("✓ Captured credentials into %s\n", result.SessionID)
				fmt.Printf("  Cookies:  %d\n", result.Cookies)
				if len(result.Headers) > 0 {
					fmt.Printf("  Headers:  %v\n", result.Headers)
				}
				if len(result.Tokens) > 0 {
					fmt.Printf("  Tokens:   %d\n", len(result.Tokens))
					for k, v := range result.Tokens {
						fmt.Printf("    %s: %s\n", k, v)
					}
				}
				fmt.Printf("\nActivate it: agentburp auth session use %s\n", result.SessionID)
			})
			return nil
		},
	}
}

func authSessionCreateCmd() *cobra.Command {
	var role string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an empty session (for manual cookie jar population)",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp auth session create admin --role admin
  agentburp auth session ingest sess_abc123 req_xyz789`,
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
			id, err := store.Create(args[0], role)
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]string{
				"session_id": id,
				"name":       args[0],
				"role":       role,
			}, func() {
				fmt.Printf("✓ Session created: %s\n", id)
				fmt.Printf("  Next: agentburp auth session ingest %s <req_id>\n", id)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "role label (admin, user, guest...)")
	return cmd
}

func authTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage auth tokens"}
	showCmd := &cobra.Command{
		Use: "show", Short: "Show tokens from the active session",
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
			sess, err := store.Active(projectName)
			if err != nil {
				return err
			}
			if sess == nil || len(sess.Tokens) == 0 {
				output.PrintAuto(map[string]interface{}{"session_id": "", "tokens": map[string]string{}}, func() {
					fmt.Println("No active tokens.")
					fmt.Println("Run: agentburp auth login --config <file>")
					fmt.Println(" or: agentburp auth session ingest <sess_id> <req_id>")
				})
				return nil
			}
			output.PrintAuto(map[string]interface{}{
				"session_id": sess.ID,
				"tokens":     sess.Tokens,
			}, func() {
				fmt.Printf("Active session: %s\n", sess.ID)
				for k, v := range sess.Tokens {
					fmt.Printf("  %s: %s\n", k, v)
				}
			})
			return nil
		},
	}
	refreshCmd := &cobra.Command{
		Use: "refresh", Short: "Re-run the auth profile to refresh tokens",
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
			sess, err := store.Active(projectName)
			if err != nil {
				return err
			}
			if sess == nil || sess.AuthProfileID == "" {
				return fmt.Errorf("no active session with an auth profile — run: agentburp auth login --config <file>")
			}
			return fmt.Errorf("token refresh for profile %q — supply the profile file: agentburp auth login --config <file>", sess.AuthProfileID)
		},
	}
	cmd.AddCommand(showCmd, refreshCmd)
	return cmd
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Passive and active security scanning",
		Long: `Two scan modes:

  passive — analyzes already-captured traffic for issues without sending new requests
            (safe, can run anytime, examines headers/cookies/responses)

  active  — sends targeted probes to detect specific vulnerabilities
            (safe mode only by default — use --allow-destructive for more aggressive checks)`,
	}
	cmd.AddCommand(scanPassiveCmd(), scanActiveCmd(), scanStatusCmd(), scanResultsCmd())
	return cmd
}

func scanPassiveCmd() *cobra.Command {
	var reqID string
	cmd := &cobra.Command{
		Use:   "passive",
		Short: "Run passive scanner on captured traffic",
		Example: `  agentburp scan passive --all --json
  agentburp scan passive --request req_abc123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			all, _ := cmd.Flags().GetBool("all")
			if !all && reqID == "" {
				return fmt.Errorf("specify --all or --request <req_id>")
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

			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"type":       "passive",
					"request_id": reqID,
					"all":        all,
					"checks":     []string{"missing-security-headers", "cookie-flags", "cors-misconfiguration", "info-disclosure", "sensitive-data-in-url", "mixed-content", "open-redirect", "csrf-token-absent", "cache-control-missing", "hsts-missing"},
					"note":       "Would analyze stored traffic and write findings (no requests sent)",
				})
				return nil
			}

			jobID, err := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{
				"type":       "passive",
				"request_id": reqID,
				"all":        all,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Printf("Running passive scan%s...\n", modeSuffix(all))
			start := time.Now()
			summary, err := scanner.RunPassive(ctx, db, proj, jobID, reqID)
			if err != nil {
				return err
			}
			output.PrintAuto(summary, func() {
				fmt.Printf("✓ Passive scan finished in %s\n", time.Since(start).Round(time.Second))
				fmt.Printf("  Traffic analyzed: %d exchanges\n", summary.Scanned)
				fmt.Printf("  New findings:     %d\n", summary.NewFindings)
				fmt.Printf("  Total findings:   %d\n", summary.TotalFindings)
				if len(summary.BySeverity) > 0 {
					fmt.Print("  By severity:      ")
					first := true
					for _, s := range []string{"critical", "high", "medium", "low", "info"} {
						if n, ok := summary.BySeverity[s]; ok {
							if !first {
								fmt.Print(", ")
							}
							fmt.Printf("%s=%d", s, n)
							first = false
						}
					}
					fmt.Println()
				}
				if summary.Note != "" {
					fmt.Printf("  Note: %s\n", summary.Note)
				}
				fmt.Printf("\nView findings: agentburp findings list --json\n")
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&reqID, "request", "", "scan a specific request")
	cmd.Flags().Bool("all", false, "scan all captured traffic")
	return cmd
}

func scanActiveCmd() *cobra.Command {
	var (
		epID             string
		safeMode         bool
		allowDestructive bool
		rateLimit        int
	)
	cmd := &cobra.Command{
		Use:   "active",
		Short: "Run active scanner (sends targeted probes)",
		Example: `  agentburp scan active --endpoint ep_abc123 --safe-mode --dry-run
  agentburp scan active --endpoint ep_abc123 --safe-mode`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if epID == "" {
				return fmt.Errorf("--endpoint <ep_id> is required — list endpoints: agentburp endpoints list")
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

			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"endpoint":          epID,
					"safe_mode":         safeMode,
					"allow_destructive": allowDestructive,
					"rate":              rateLimit,
					"checks":            []string{"reflected-xss", "sqli-error", "idor-signal", "auth-bypass"},
					"note":              "Would send non-destructive probes to the endpoint (scope-enforced, rate-limited)",
				})
				return nil
			}

			jobID, err := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{
				"type":      "active",
				"endpoint":  epID,
				"safe_mode": safeMode,
				"rate":      rateLimit,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Printf("Running active scan on %s (safe probes only)...\n", epID)
			start := time.Now()
			summary, err := scanner.RunActive(ctx, db, proj, jobID, scanner.ActiveOptions{
				EndpointID: epID,
				Rate:       rateLimit,
			})
			if err != nil {
				return err
			}
			output.PrintAuto(summary, func() {
				fmt.Printf("✓ Active scan finished in %s\n", time.Since(start).Round(time.Second))
				fmt.Printf("  Probes sent:      %d\n", summary.ProbesSent)
				if summary.ProbesSkipped > 0 {
					fmt.Printf("  Probes skipped:   %d\n", summary.ProbesSkipped)
					reasons := make([]string, 0, len(summary.SkippedReasons))
					for r, c := range summary.SkippedReasons {
						reasons = append(reasons, fmt.Sprintf("%s x%d", r, c))
					}
					sort.Strings(reasons)
					fmt.Printf("    reasons: %s\n", strings.Join(reasons, ", "))
				}
				fmt.Printf("  Signals detected: %d\n", summary.NewFindings)
				if len(summary.ByCheck) > 0 {
					for _, c := range scanner.SortedByCheck(summary.ByCheck) {
						fmt.Printf("    %-16s %d\n", c, summary.ByCheck[c])
					}
				}
				if summary.Note != "" {
					fmt.Printf("  Note: %s\n", summary.Note)
				}
				fmt.Printf("\nView findings: agentburp findings list --type active\n")
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&epID, "endpoint", "", "endpoint ID to scan")
	cmd.Flags().BoolVar(&safeMode, "safe-mode", true, "only safe, non-destructive probes")
	cmd.Flags().BoolVar(&allowDestructive, "allow-destructive", false, "allow more aggressive checks (use with caution)")
	cmd.Flags().IntVar(&rateLimit, "rate", 10, "max probes per second")
	return cmd
}

func scanStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status <job_id>", Short: "Check scan job status",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			job, err := core.NewJobStore(db).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{
				"job_id": args[0], "status": job.Status, "type": job.Type,
				"summary": job.ResultSummary,
			}, func() {
				fmt.Printf("Scan job %s (%s): %s\n", args[0], job.Type, job.Status)
				if len(job.ResultSummary) > 0 {
					output.PrintKV(job.ResultSummary)
				}
			})
			return nil
		},
	}
}

func scanResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use: "results <job_id>", Short: "Show scan results",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			job, err := core.NewJobStore(db).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{
				"job_id": args[0], "status": job.Status, "summary": job.ResultSummary,
			}, func() {
				fmt.Printf("Scan results for %s (status: %s):\n", args[0], job.Status)
				output.PrintKV(job.ResultSummary)
			})
			return nil
		},
	}
}

func newFindingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "View and manage security findings",
		Long: `Findings are security signals discovered by the passive/active scanner
or added manually. Each finding has:
  • ID (sig_*)
  • Severity: critical | high | medium | low | info
  • Confidence: high | medium | low
  • Evidence: request/response/description
  • Explanation and remediation guidance`,
	}
	cmd.AddCommand(
		findingsListCmd(),
		findingsShowCmd(),
		findingsAddCmd(),
		findingsMarkFPCmd(),
		findingsUnmarkFPCmd(),
		findingsRetestCmd(),
		findingsEvidenceCmd(),
	)
	return cmd
}

func findingsListCmd() *cobra.Command {
	var (
		severity string
		sigType  string
		epID     string
	)
	cmd := &cobra.Command{
		Use: "list", Short: "List all findings",
		Example: `  agentburp findings list --json
  agentburp findings list --severity high,critical
  agentburp findings list --endpoint ep_abc123`,
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

			query := `SELECT id, type, check_id, title, severity, confidence, endpoint_id, false_positive, created_at
			          FROM signals WHERE project_id = ? AND false_positive = 0`
			queryArgs := []interface{}{proj.ID}
			if epID != "" {
				query += " AND endpoint_id = ?"
				queryArgs = append(queryArgs, epID)
			}
			if sigType != "" {
				query += " AND type = ?"
				queryArgs = append(queryArgs, sigType)
			}
			if severity != "" {
				sevList := strings.Split(severity, ",")
				placeholders := make([]string, len(sevList))
				for i, s := range sevList {
					placeholders[i] = "?"
					queryArgs = append(queryArgs, strings.TrimSpace(s))
				}
				query += " AND severity IN (" + strings.Join(placeholders, ",") + ")"
			}
			query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"

			rows, err := db.Conn().Query(query, queryArgs...)
			if err != nil {
				return err
			}
			defer rows.Close()

			type F struct {
				ID            string `json:"id"`
				Type          string `json:"type"`
				CheckID       string `json:"check_id"`
				Title         string `json:"title"`
				Severity      string `json:"severity"`
				Confidence    string `json:"confidence"`
				EndpointID    string `json:"endpoint_id"`
				FalsePositive bool   `json:"false_positive"`
				CreatedAt     string `json:"created_at"`
			}
			var findings []F
			for rows.Next() {
				var f F
				var fpInt int
				var epIDNull, createdAt interface{}
				rows.Scan(&f.ID, &f.Type, &f.CheckID, &f.Title, &f.Severity,
					&f.Confidence, &epIDNull, &fpInt, &createdAt)
				f.FalsePositive = fpInt == 1
				if epIDNull != nil {
					f.EndpointID = epIDNull.(string)
				}
				if createdAt != nil {
					f.CreatedAt = createdAt.(string)
				}
				findings = append(findings, f)
			}

			output.PrintAuto(findings, func() {
				if len(findings) == 0 {
					fmt.Println("No findings yet.")
					fmt.Println("Run: agentburp scan passive --all")
					return
				}
				output.PrintTable(
					[]string{"ID", "SEVERITY", "TITLE", "CONFIDENCE", "TYPE"},
					func() [][]string {
						var r [][]string
						for _, f := range findings {
							r = append(r, []string{
								core.ShortID(f.ID), f.Severity, f.Title, f.Confidence, f.Type,
							})
						}
						return r
					}(),
				)
				fmt.Printf("\n%d findings\n", len(findings))
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&severity, "severity", "", "filter: critical|high|medium|low|info (comma-separated)")
	cmd.Flags().StringVar(&sigType, "type", "", "filter: passive|active|manual")
	cmd.Flags().StringVar(&epID, "endpoint", "", "filter by endpoint ID")
	return cmd
}

func findingsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use: "show <sig_id>", Short: "Show full finding details with evidence",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			row := db.Conn().QueryRow(`
				SELECT id, type, check_id, title, severity, confidence, endpoint_id,
				       request_id, response_id, evidence_json, explanation, remediation,
				       false_positive, retested, created_at
				FROM signals WHERE id = ?`, args[0])
			var sig struct {
				ID            string                 `json:"id"`
				Type          string                 `json:"type"`
				CheckID       string                 `json:"check_id"`
				Title         string                 `json:"title"`
				Severity      string                 `json:"severity"`
				Confidence    string                 `json:"confidence"`
				EndpointID    string                 `json:"endpoint_id"`
				RequestID     string                 `json:"request_id"`
				ResponseID    string                 `json:"response_id"`
				Evidence      map[string]interface{} `json:"evidence"`
				Explanation   string                 `json:"explanation"`
				Remediation   string                 `json:"remediation"`
				FalsePositive bool                   `json:"false_positive"`
				Retested      bool                   `json:"retested"`
				CreatedAt     string                 `json:"created_at"`
			}
			var evJSON string
			var fpInt, retestInt int
			if err := row.Scan(
				&sig.ID, &sig.Type, &sig.CheckID, &sig.Title, &sig.Severity, &sig.Confidence,
				&sig.EndpointID, &sig.RequestID, &sig.ResponseID, &evJSON,
				&sig.Explanation, &sig.Remediation, &fpInt, &retestInt, &sig.CreatedAt,
			); err != nil {
				return fmt.Errorf("finding %q not found", args[0])
			}
			json.Unmarshal([]byte(evJSON), &sig.Evidence)
			sig.FalsePositive = fpInt == 1
			sig.Retested = retestInt == 1

			output.PrintAuto(sig, func() {
				fmt.Printf("━━━ FINDING ━━━ %s\n", sig.ID)
				fmt.Printf("  Title:       %s\n", sig.Title)
				fmt.Printf("  Severity:    %s\n", sig.Severity)
				fmt.Printf("  Confidence:  %s\n", sig.Confidence)
				fmt.Printf("  Type:        %s (%s)\n", sig.Type, sig.CheckID)
				if sig.EndpointID != "" {
					fmt.Printf("  Endpoint:    %s\n", sig.EndpointID)
				}
				fmt.Printf("\nExplanation:\n  %s\n", sig.Explanation)
				if sig.Remediation != "" {
					fmt.Printf("\nRemediation:\n  %s\n", sig.Remediation)
				}
			})
			return nil
		},
	}
}

func findingsAddCmd() *cobra.Command {
	var (
		epID       string
		title      string
		sev        string
		confidence string
		explain    string
	)
	cmd := &cobra.Command{
		Use: "add", Short: "Add a manual finding",
		Example: `  agentburp findings add --endpoint ep_abc123 --title "IDOR via user_id" --severity high`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if title == "" || sev == "" {
				return fmt.Errorf("--title and --severity are required")
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
			id := core.NewID("sig")
			now := core.TimestampNow()

			var epIDVal interface{}
			if epID != "" {
				epIDVal = epID
			}
			_, dbErr := db.Conn().Exec(`
				INSERT INTO signals (id, project_id, type, check_id, title, severity, confidence, endpoint_id, evidence_json, explanation, created_at)
				VALUES (?, ?, 'manual', 'manual', ?, ?, ?, ?, '{}', ?, ?)`,
				id, proj.ID, title, sev, confidence, epIDVal, explain, now,
			)
			if dbErr != nil {
				return fmt.Errorf("insert finding: %w", dbErr)
			}
			output.PrintAuto(map[string]string{"id": id, "title": title, "severity": sev}, func() {
				fmt.Printf("✓ Finding added: %s\n  %s [%s]\n", id, title, sev)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&epID, "endpoint", "", "associated endpoint ID")
	cmd.Flags().StringVar(&title, "title", "", "finding title (required)")
	cmd.Flags().StringVar(&sev, "severity", "", "severity: critical|high|medium|low|info (required)")
	cmd.Flags().StringVar(&confidence, "confidence", "medium", "confidence: high|medium|low")
	cmd.Flags().StringVar(&explain, "explanation", "", "explanation text")
	return cmd
}

func findingsMarkFPCmd() *cobra.Command {
	return &cobra.Command{
		Use: "mark-fp <sig_id>", Short: "Mark a finding as a false positive",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			db.Conn().Exec(`UPDATE signals SET false_positive = 1 WHERE id = ?`, args[0])
			output.Success(fmt.Sprintf("Finding %s marked as false positive", args[0]), nil)
			return nil
		},
	}
}

func findingsUnmarkFPCmd() *cobra.Command {
	return &cobra.Command{
		Use: "unmark-fp <sig_id>", Short: "Unmark a finding previously marked as false positive",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			db.Conn().Exec(`UPDATE signals SET false_positive = 0 WHERE id = ?`, args[0])
			output.Success(fmt.Sprintf("Finding %s unmarked as false positive", args[0]), nil)
			return nil
		},
	}
}

func findingsRetestCmd() *cobra.Command {
	return &cobra.Command{
		Use: "retest <sig_id>", Short: "Re-run the scanner check for a finding",
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

			store := scanner.NewFindingsStore(db, proj.ID)
			sig, err := store.Get(args[0])
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Printf("Retesting finding %s (%s/%s)...\n", sig.ID, sig.Type, sig.CheckID)

			var summary *scanner.ScanSummary
			switch sig.Type {
			case "passive":
				if sig.RequestID == "" {
					return fmt.Errorf("finding has no linked request to re-analyze")
				}
				jobID, err := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{
					"type": "passive", "request_id": sig.RequestID, "retest_of": sig.ID,
				})
				if err != nil {
					return err
				}
				summary, err = scanner.RunPassive(ctx, db, proj, jobID, sig.RequestID)
				if err != nil {
					return err
				}
			case "active":
				if sig.EndpointID == "" {
					return fmt.Errorf("finding has no linked endpoint to re-probe")
				}
				jobID, err := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{
					"type": "active", "endpoint": sig.EndpointID, "retest_of": sig.ID,
				})
				if err != nil {
					return err
				}
				summary, err = scanner.RunActive(ctx, db, proj, jobID, scanner.ActiveOptions{EndpointID: sig.EndpointID, Rate: 10})
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("finding type %q cannot be retested", sig.Type)
			}

			if err := store.MarkRetested(sig.ID); err != nil {
				return err
			}

			stillOpen := false
			if sig.Type == "active" {

				list, _ := store.List("", sig.Type, sig.EndpointID, true)
				for _, f := range list {
					if f.CheckID == sig.CheckID && !f.FalsePositive {
						stillOpen = true
					}
				}
			} else {
				stillOpen = summary.NewFindings > 0
			}

			output.PrintAuto(map[string]interface{}{
				"sig_id":       sig.ID,
				"retested":     true,
				"reconfirmed":  stillOpen,
				"new_findings": summary.NewFindings,
			}, func() {
				if stillOpen {
					fmt.Printf("✓ Retest complete: finding %s reconfirmed (issue still present)\n", sig.ID)
				} else {
					fmt.Printf("✓ Retest complete: finding %s NOT reconfirmed — review and mark as resolved if no longer valid\n", sig.ID)
				}
			})
			return nil
		},
	}
}

func findingsEvidenceCmd() *cobra.Command {
	return &cobra.Command{
		Use: "evidence <sig_id>", Short: "Show evidence for a finding",
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

			store := scanner.NewFindingsStore(db, proj.ID)
			sig, err := store.Get(args[0])
			if err != nil {
				return err
			}

			output.PrintAuto(map[string]interface{}{
				"sig_id":      sig.ID,
				"evidence":    sig.Evidence,
				"request_id":  sig.RequestID,
				"response_id": sig.ResponseID,
			}, func() {
				fmt.Printf("Evidence for finding %s\n", sig.ID)
				fmt.Printf("  Check:       %s\n", sig.CheckID)
				fmt.Printf("  Endpoint:    %s\n", sig.EndpointID)
				fmt.Printf("  Request:     %s\n", sig.RequestID)
				fmt.Printf("  Response:    %s\n", sig.ResponseID)
				if len(sig.Evidence) > 0 {
					fmt.Println("  Evidence:")
					for k, v := range sig.Evidence {
						b, _ := json.Marshal(v)
						fmt.Printf("    %-18s %s\n", k+":", string(b))
					}
				}
				if sig.RequestID != "" {
					fmt.Printf("\n  Linked exchange: agentburp history show %s\n", sig.RequestID)
				}
			})
			return nil
		},
	}
}
