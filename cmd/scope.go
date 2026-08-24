package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/scope"
	"github.com/spf13/cobra"
)

func newScopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Manage target scope rules",
		Long: `Scope rules control which URLs the proxy captures and which tools can interact with.

The scope engine is BLOCKING — out-of-scope requests are rejected, not just flagged.
All violations are logged to the audit log.

Pattern types:
  host    — match by hostname (supports *.example.com wildcards)
  url     — match by URL prefix
  regex   — match by regular expression`,
	}
	cmd.AddCommand(
		scopeAddCmd(),
		scopeRemoveCmd(),
		scopeListCmd(),
		scopeCheckCmd(),
	)
	return cmd
}

func scopeAddCmd() *cobra.Command {
	var (
		include     bool
		exclude     bool
		patternType string
	)
	cmd := &cobra.Command{
		Use:   "add <pattern>",
		Short: "Add a scope rule",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp scope add "app.example.com" --include
  agentburp scope add "*.example.com" --include
  agentburp scope add "https://app.example.com/api" --include --type url
  agentburp scope add ".*\\.staging\\..*" --exclude --type regex`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !include && !exclude {
				return fmt.Errorf("specify --include or --exclude")
			}
			if include && exclude {
				return fmt.Errorf("cannot use both --include and --exclude")
			}
			action := "include"
			if exclude {
				action = "exclude"
			}

			pattern := args[0]
			resolved := inferScopeType(&pattern, patternType)

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
			engine, err := scope.NewEngine(db, proj.ID)
			if err != nil {
				return err
			}
			rule, err := engine.AddRule(action, pattern, resolved)
			if err != nil {
				return err
			}
			output.PrintAuto(rule, func() {
				fmt.Printf("✓ Scope rule added: [%s] %s (%s)\n", action, pattern, resolved)
				if resolved != patternType {
					fmt.Printf("  (auto-detected %q — a full URL matches by prefix)\n", resolved)
				}
				fmt.Printf("  Rule ID: %s\n", rule.ID)
			})
			return nil
		},
	}
	cmd.Flags().BoolVar(&include, "include", false, "include pattern in scope")
	cmd.Flags().BoolVar(&exclude, "exclude", false, "exclude pattern from scope")
	cmd.Flags().StringVar(&patternType, "type", "host", "pattern type: host|url|regex")
	return cmd
}

func inferScopeType(pattern *string, requested string) string {
	if requested != "host" {
		return requested
	}
	raw := *pattern

	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		*pattern = u.Scheme + "://" + u.Host
		return "url"
	}

	if idx := strings.IndexByte(raw, ':'); idx > 0 {
		*pattern = raw[:idx]
	}
	return "host"
}

func scopeRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <rule_id>",
		Short: "Remove a scope rule",
		Args:  cobra.ExactArgs(1),
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
			engine, err := scope.NewEngine(db, proj.ID)
			if err != nil {
				return err
			}
			if err := engine.RemoveRule(args[0]); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Scope rule %s removed", args[0]), nil)
			return nil
		},
	}
}

func scopeListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all scope rules",
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
			engine, err := scope.NewEngine(db, proj.ID)
			if err != nil {
				return err
			}
			rules := engine.ListRules()
			output.PrintAuto(rules, func() {
				if len(rules) == 0 {
					fmt.Println("No scope rules configured. All traffic is in scope.")
					fmt.Println("Add rules: agentburp scope add <target> --include")
					return
				}
				headers := []string{"ID", "ACTION", "TYPE", "PATTERN"}
				var rows [][]string
				for _, r := range rules {
					rows = append(rows, []string{r.ID, r.Action, r.PatternType, r.Pattern})
				}
				output.PrintTable(headers, rows)
			})
			return nil
		},
	}
}

func scopeCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <url>",
		Short: "Check whether a URL is in scope",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp scope check https://app.example.com/api/users
  agentburp scope check https://app.example.com/api/users --json`,
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
			engine, err := scope.NewEngine(db, proj.ID)
			if err != nil {
				return err
			}
			result := engine.Check(args[0])
			output.PrintAuto(result, func() {
				if result.InScope {
					fmt.Printf("✓ IN SCOPE: %s\n", args[0])
					fmt.Printf("  Reason: %s\n", result.Reason)
					if result.Rule != "" {
						fmt.Printf("  Matched rule: %s\n", result.Rule)
					}
				} else {
					fmt.Printf("✗ OUT OF SCOPE: %s\n", args[0])
					fmt.Printf("  Reason: %s\n", result.Reason)
					if result.Rule != "" {
						fmt.Printf("  Matched rule: %s\n", result.Rule)
					}
				}
			})
			return nil
		},
	}
}
