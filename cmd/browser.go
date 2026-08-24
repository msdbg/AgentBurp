package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/auth"
	"github.com/msdbg/AgentBurp/internal/browser"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newBrowserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "browser",
		Short: "Browser Session Engine — real Chrome with stealth for WAF/CDN/JS challenges",
		Long: `Browser Session Engine manages real Chrome instances via go-rod + stealth.

Use for:
  • JavaScript challenge cookies
  • CDN bot checks (Cloudflare etc.)
  • Device fingerprinting bypass
  • Interactive login flows requiring human assistance
  • Client-side request signing via JS bridge

Workflow:
  agentburp browser open https://target.example.com/login --profile stealth --json
  agentburp browser cookies export --session dashboard-session --json
  agentburp auth session use dashboard-session --json`,
	}
	cmd.AddCommand(
		browserOpenCmd(),
		browserStatusCmd(),
		browserListCmd(),
		browserWaitCmd(),
		browserExecuteCmd(),
		browserFetchCmd(),
		browserCookiesCmd(),
		browserStorageCmd(),
		browserCloseCmd(),
	)
	return cmd
}

func browserOpenCmd() *cobra.Command {
	var (
		profile      string
		headed       bool
		waitForHuman bool
		sessionName  string
		timeout      int
	)
	cmd := &cobra.Command{
		Use:   "open <url>",
		Short: "Open URL in managed browser",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp browser open https://target.example.com/login --profile stealth --json
  agentburp browser open https://target.example.com/login --headed --wait-for-human --json
  agentburp browser open https://app.example.com --profile stealth --session my-browser --json`,
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
			if profile == "" {
				profile = "stealth"
			}
			if sessionName == "" {
				sessionName = fmt.Sprintf("browser-%d", time.Now().Unix()%10000)
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"url": targetURL, "profile": profile, "headed": headed, "wait_for_human": waitForHuman,
					"note": "Would launch Chrome, navigate, and capture session",
				})
				return nil
			}
			mgr := browser.NewManager(db, proj.ID)
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}
			sess, err := mgr.Open(ctx, targetURL, profile, headed, waitForHuman, sessionName)
			if err != nil {
				return err
			}
			result := map[string]interface{}{
				"browser_session_id": sess.ID,
				"name":               sess.Name,
				"status":             sess.Status,
				"current_url":        sess.CurrentURL,
				"profile":            sess.Profile,
				"headed":             headed,
				"wait_for_human":     waitForHuman,
			}
			if sess.Status == "error" {
				result["warning"] = "Browser failed to launch — session is in degraded mode. Install Chrome or use --headed on a machine with display. Cookies/storage will be empty until a real browser opens."
			}
			if waitForHuman && sess.Status == "waiting_human" {
				result["next"] = "Human: complete CAPTCHA/MFA in the visible browser, then run: agentburp browser cookies export --browser " + sess.ID + " --session my-session --json"
			}
			output.PrintAuto(result, func() {
				if sess.Status == "error" {
					fmt.Printf("⚠ Browser session %s (degraded): %s\n", sess.ID, sess.Name)
					fmt.Printf("  URL: %s | Profile: %s | Status: error — Chrome not available\n", targetURL, profile)
					fmt.Printf("  Fix: install Chrome or run with --headed on headed machine\n")
				} else if waitForHuman {
					fmt.Printf("✓ Browser opened (headed, waiting for human): %s\n", sess.ID)
					fmt.Printf("  URL: %s\n  Complete the challenge in the visible browser window.\n", targetURL)
					fmt.Printf("  Then: agentburp browser cookies export --browser %s --session my-session\n", sess.ID)
				} else {
					fmt.Printf("✓ Browser opened: %s\n", sess.ID)
					fmt.Printf("  URL: %s | Profile: %s | Status: %s\n", targetURL, profile, sess.Status)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "stealth", "browser profile: stealth|default")
	cmd.Flags().BoolVar(&headed, "headed", false, "run visible browser (required for --wait-for-human, CAPTCHA/MFA)")
	cmd.Flags().BoolVar(&waitForHuman, "wait-for-human", false, "pause for human to complete CAPTCHA/MFA in headed browser")
	cmd.Flags().StringVar(&sessionName, "session", "", "name for browser session (optional)")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "navigation timeout in seconds")
	return cmd
}

func browserStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [browser_id|name]",
		Short: "Show browser session status",
		Example: `  agentburp browser status --json
  agentburp browser status bses_abc123 --json`,
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
			mgr := browser.NewManager(db, proj.ID)
			if len(args) > 0 {
				sess, err := mgr.Status(args[0])
				if err != nil {
					return err
				}
				output.PrintAuto(sess, func() {
					fmt.Printf("Browser %s: %s | %s | %s\n", sess.ID, sess.Status, sess.Profile, sess.CurrentURL)
				})
				return nil
			}
			list, err := mgr.List()
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No browser sessions. Open one: agentburp browser open <url> --profile stealth")
					return
				}
				fmt.Printf("Browser sessions (%d):\n", len(list))
				for _, s := range list {
					fmt.Printf("  %s  %-12s  %-10s  %s\n", core.ShortID(s.ID), s.Name, s.Status, s.CurrentURL)
				}
			})
			return nil
		},
	}
}

func browserListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List browser sessions (alias for status)",
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
			mgr := browser.NewManager(db, proj.ID)
			list, err := mgr.List()
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No browser sessions.")
					return
				}
				for _, s := range list {
					fmt.Printf("  %s  %s  %s\n", s.ID, s.Status, s.CurrentURL)
				}
			})
			return nil
		},
	}
}

func browserWaitCmd() *cobra.Command {
	var (
		selector    string
		urlContains string
		networkIdle bool
		timeout     int
		browserID   string
	)
	cmd := &cobra.Command{
		Use:   "wait",
		Short: "Wait for condition in browser page",
		Example: `  agentburp browser wait --selector "#username" --browser bses_abc123
  agentburp browser wait --url-contains "/dashboard" --browser bses_abc123
  agentburp browser wait --network-idle --browser bses_abc123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if selector == "" && urlContains == "" && !networkIdle {
				return fmt.Errorf("specify --selector, --url-contains, or --network-idle")
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
			if browserID == "" {
				// Use latest session
				mgr := browser.NewManager(db, proj.ID)
				list, _ := mgr.List()
				if len(list) == 0 {
					return fmt.Errorf("no browser session — open one: agentburp browser open <url>")
				}
				browserID = list[0].ID
			}
			mgr := browser.NewManager(db, proj.ID)
			to := time.Duration(timeout) * time.Second
			if selector != "" {
				if err := mgr.WaitForSelector(browserID, selector, to); err != nil {
					return err
				}
				output.PrintAuto(map[string]string{"status": "ok", "wait": "selector", "selector": selector}, func() {
					fmt.Printf("✓ Selector %q found\n", selector)
				})
				return nil
			}
			if urlContains != "" {
				if err := mgr.WaitForURL(browserID, urlContains, to); err != nil {
					return err
				}
				output.PrintAuto(map[string]string{"status": "ok", "wait": "url_contains", "contains": urlContains}, func() {
					fmt.Printf("✓ URL now contains %q\n", urlContains)
				})
				return nil
			}
			if networkIdle {
				if err := mgr.WaitForNetworkIdle(browserID, to); err != nil {
					return err
				}
				output.PrintAuto(map[string]string{"status": "ok", "wait": "network_idle"}, func() {
					fmt.Printf("✓ Network idle\n")
				})
				return nil
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&selector, "selector", "", "CSS selector to wait for")
	cmd.Flags().StringVar(&urlContains, "url-contains", "", "wait until URL contains this substring")
	cmd.Flags().BoolVar(&networkIdle, "network-idle", false, "wait for network idle")
	cmd.Flags().IntVar(&timeout, "timeout", 15, "timeout in seconds")
	cmd.Flags().StringVar(&browserID, "browser", "", "browser session ID (default: latest)")
	return cmd
}

func browserExecuteCmd() *cobra.Command {
	var (
		browserID string
		filePath  string
	)
	cmd := &cobra.Command{
		Use:   "execute <js>",
		Short: "Execute JavaScript in browser page (JS bridge)",
		Long: `Executes JavaScript in the browser page context. Use to call app signing functions.

Examples:
  agentburp browser execute "return document.title" --browser bses_abc123 --json
  agentburp browser execute "return window.app.signPayload({id:1})" --browser bses_abc123 --json
  agentburp browser execute-file scripts/sign.js --browser bses_abc123 --json`,
		Args: cobra.RangeArgs(0, 1),
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
			if browserID == "" {
				mgr := browser.NewManager(db, proj.ID)
				list, _ := mgr.List()
				if len(list) == 0 {
					return fmt.Errorf("no browser session — open one first")
				}
				browserID = list[0].ID
			}
			var js string
			if filePath != "" {
				b, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("read file %q: %w", filePath, err)
				}
				js = string(b)
			} else if len(args) > 0 {
				js = args[0]
			} else {
				return fmt.Errorf("provide JS expression or --file")
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{"browser": browserID, "js": js[:min(100, len(js))]})
				return nil
			}
			mgr := browser.NewManager(db, proj.ID)
			result, err := mgr.Execute(browserID, js)
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{"result": result, "browser": browserID}, func() {
				b, _ := json.MarshalIndent(result, "", "  ")
				fmt.Printf("Result:\n%s\n", b)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&browserID, "browser", "", "browser session ID (default: latest)")
	cmd.Flags().StringVar(&filePath, "file", "", "JS file to execute (alternative to inline)")
	return cmd
}

func browserFetchCmd() *cobra.Command {
	var (
		browserID string
		method    string
		urlStr    string
		jsonBody  string
		headers   []string
		timeout   int
	)
	cmd := &cobra.Command{
		Use:     "fetch",
		Short:   "Execute fetch inside browser (browser-fetch transport)",
		Example: `  agentburp browser fetch --method POST --url https://app.example.com/api/order --json-body '{"amount":10}' --browser bses_abc123 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if urlStr == "" {
				return fmt.Errorf("--url is required")
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
			if browserID == "" {
				mgr := browser.NewManager(db, proj.ID)
				list, _ := mgr.List()
				if len(list) == 0 {
					return fmt.Errorf("no browser session")
				}
				browserID = list[0].ID
			}
			hmap := map[string]string{}
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					hmap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{"browser": browserID, "method": method, "url": urlStr})
				return nil
			}
			mgr := browser.NewManager(db, proj.ID)
			res, err := mgr.Fetch(browserID, method, urlStr, jsonBody, hmap, time.Duration(timeout)*time.Second)
			if err != nil {
				return err
			}
			// Store in history if requested
			output.PrintAuto(res, func() {
				fmt.Printf("Browser fetch: %v\n", res["status"])
				if body, ok := res["body"]; ok {
					s := fmt.Sprint(body)
					if len(s) > 500 {
						s = s[:500] + "..."
					}
					fmt.Printf("Body: %s\n", s)
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&browserID, "browser", "", "browser session ID (default: latest)")
	cmd.Flags().StringVar(&method, "method", "GET", "HTTP method")
	cmd.Flags().StringVar(&urlStr, "url", "", "URL to fetch (required)")
	cmd.Flags().StringVar(&jsonBody, "json-body", "", "JSON body")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "headers (Name: Value)")
	cmd.Flags().IntVar(&timeout, "timeout", 30, "timeout seconds")
	return cmd
}

func browserCookiesCmd() *cobra.Command {
	var (
		browserID   string
		sessionName string
		asSession   string
	)
	cmd := &cobra.Command{
		Use:   "cookies",
		Short: "Cookie management for browser sessions",
	}
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export browser cookies (and optionally create AgentBurp session)",
		Example: `  agentburp browser cookies export --json
  agentburp browser cookies export --browser bses_abc123 --session my-session --json
  agentburp browser cookies export --browser bses_abc123 --session my-session --json --use`,
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
			mgr := browser.NewManager(db, proj.ID)
			if browserID == "" {
				list, _ := mgr.List()
				if len(list) == 0 {
					return fmt.Errorf("no browser session — open one: agentburp browser open <url>")
				}
				browserID = list[0].ID
			}
			cookies, err := mgr.Cookies(browserID)
			if err != nil {
				return err
			}
			// If cookies empty and degraded, warn
			result := map[string]interface{}{
				"browser_session": browserID,
				"cookies":         cookies,
				"count":           len(cookies),
			}
			// Optionally create/update AgentBurp session
			targetSession := sessionName
			if targetSession == "" {
				targetSession = asSession
			}
			if targetSession != "" {
				store := auth.NewSessionStore(db, proj.ID)
				// Create or get session
				var sessID string
				// Try to find existing session by name
				rows, _ := db.Conn().Query(`SELECT id FROM sessions WHERE project_id = ? AND name = ?`, proj.ID, targetSession)
				if rows != nil {
					if rows.Next() {
						rows.Scan(&sessID)
					}
					rows.Close()
				}
				if sessID == "" {
					sessID, err = store.Create(targetSession, "browser")
					if err != nil {
						return fmt.Errorf("create session: %w", err)
					}
				}
				sess, err := store.Get(sessID)
				if err != nil {
					return err
				}
				// Convert browser cookies to session cookies
				var setCookies []string
				for _, c := range cookies {
					name := c["name"]
					val := c["value"]
					if name != "" {
						setCookies = append(setCookies, fmt.Sprintf("%s=%s", name, val))
					}
				}
				if len(setCookies) > 0 {
					store.SetCookies(sess, setCookies)
					// Also persist via Update
					store.Save(sess)
				}
				result["session_id"] = sessID
				result["session_name"] = targetSession
				// Check if --use flag is set
				useFlag, _ := cmd.Flags().GetBool("use")
				if useFlag {
					auth.SetActiveSession(projectName, sessID)
					result["active"] = true
				}
			}
			output.PrintAuto(result, func() {
				fmt.Printf("✓ Exported %d cookies from browser %s\n", len(cookies), core.ShortID(browserID))
				for _, c := range cookies {
					fmt.Printf("  %s=%s (domain=%s)\n", c["name"], c["value"], c["domain"])
				}
				if targetSession != "" {
					fmt.Printf("\n✓ Session %q ready: %s\n", targetSession, result["session_id"])
					if result["active"] == true {
						fmt.Printf("  Active session set.\n")
					} else {
						fmt.Printf("  Activate: agentburp auth session use %s\n", result["session_id"])
					}
				}
			})
			return nil
		},
	}
	exportCmd.Flags().StringVar(&browserID, "browser", "", "browser session ID (default: latest)")
	exportCmd.Flags().StringVar(&sessionName, "session", "", "create/update AgentBurp session with these cookies (e.g. dashboard-session)")
	exportCmd.Flags().StringVar(&asSession, "as-session", "", "alias for --session")
	exportCmd.Flags().Bool("use", false, "also set as active session (equivalent to auth session use)")
	cmd.AddCommand(exportCmd)
	return cmd
}

func browserStorageCmd() *cobra.Command {
	var (
		browserID   string
		storageType string
		sessionName string
	)
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Storage export for browser sessions",
	}
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export localStorage / sessionStorage",
		Example: `  agentburp browser storage export --json
  agentburp browser storage export --type localStorage --browser bses_abc123 --json
  agentburp browser storage export --type sessionStorage --browser bses_abc123 --session my-session --json`,
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
			if browserID == "" {
				mgr := browser.NewManager(db, proj.ID)
				list, _ := mgr.List()
				if len(list) == 0 {
					return fmt.Errorf("no browser session")
				}
				browserID = list[0].ID
			}
			mgr := browser.NewManager(db, proj.ID)
			data, err := mgr.Storage(browserID, storageType)
			if err != nil {
				return err
			}
			result := map[string]interface{}{
				"browser_session": browserID,
				"type":            storageType,
				"data":            data,
				"count":           len(data),
			}
			// Optionally save tokens to session
			if sessionName != "" && len(data) > 0 {
				store := auth.NewSessionStore(db, proj.ID)
				var sessID string
				rows, _ := db.Conn().Query(`SELECT id FROM sessions WHERE project_id = ? AND name = ?`, proj.ID, sessionName)
				if rows != nil {
					if rows.Next() {
						rows.Scan(&sessID)
					}
					rows.Close()
				}
				if sessID == "" {
					sessID, _ = store.Create(sessionName, "browser")
				}
				if sessID != "" {
					sess, _ := store.Get(sessID)
					if sess != nil {
						tokens := map[string]string{}
						for k, v := range data {
							// Heuristic: token-like keys
							lk := strings.ToLower(k)
							if strings.Contains(lk, "token") || strings.Contains(lk, "auth") || strings.Contains(lk, "jwt") || strings.Contains(lk, "bearer") {
								tokens[k] = v
							}
						}
						if len(tokens) > 0 {
							store.SetTokens(sess, tokens)
							store.Save(sess)
							result["session_id"] = sessID
							result["tokens_extracted"] = len(tokens)
						}
					}
				}
			}
			output.PrintAuto(result, func() {
				fmt.Printf("✓ Exported %d keys from %s\n", len(data), storageType)
				for k, v := range data {
					val := v
					if len(val) > 80 {
						val = val[:77] + "..."
					}
					fmt.Printf("  %s = %s\n", k, val)
				}
			})
			return nil
		},
	}
	exportCmd.Flags().StringVar(&browserID, "browser", "", "browser session ID")
	exportCmd.Flags().StringVar(&storageType, "type", "localStorage", "storage type: localStorage|sessionStorage")
	exportCmd.Flags().StringVar(&sessionName, "session", "", "save token-like entries to AgentBurp session")
	cmd.AddCommand(exportCmd)
	return cmd
}

func browserCloseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "close [browser_id|name]",
		Short: "Close browser session",
		Args:  cobra.MaximumNArgs(1),
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
			mgr := browser.NewManager(db, proj.ID)
			var target string
			if len(args) > 0 {
				target = args[0]
			} else {
				list, _ := mgr.List()
				if len(list) == 0 {
					return fmt.Errorf("no browser sessions to close")
				}
				target = list[0].ID
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{"would_close": target})
				return nil
			}
			if err := mgr.Close(target); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Browser session %s closed", core.ShortID(target)), nil)
			return nil
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure imports used
var _ = json.Marshal
var _ = models.Session{}
