package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/msdbg/AgentBurp/internal/authmacro"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newAuthMacroCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "macro",
		Short: "Auth macro engine for SSO/OAuth/MFA flows",
		Long: `Auth macros are repeatable authentication workflows.

Types: simple_login, oauth_authorization_code, oidc_flow, saml_redirect,
       browser_assisted_login, human_assisted_mfa, token_refresh

Steps can be browser actions (browser_open, wait_selector, browser_type, browser_click,
wait_url, export_cookies, extract_token) or HTTP steps (http_request, extract_json).`,
	}
	cmd.AddCommand(
		authMacroCreateCmd(),
		authMacroListCmd(),
		authMacroShowCmd(),
		authMacroRunCmd(),
		authMacroDeleteCmd(),
	)
	return cmd
}

func authMacroCreateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create auth macro from YAML",
		Example: `  agentburp auth macro create --file auth/sso_login.yaml --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
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
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{"file": file, "size": len(data), "would_create": true})
				return nil
			}
			store := authmacro.NewStore(db, proj.ID)
			id, err := store.Create("", string(data))
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"id": id, "file": file}, func() {
				fmt.Printf("✓ Auth macro created: %s\n", id)
				fmt.Printf("  Run: agentburp auth macro run %s --json\n", id)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "YAML file (required)")
	return cmd
}

func authMacroListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List auth macros",
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
			list, err := authmacro.NewStore(db, proj.ID).List()
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No auth macros. Create one: agentburp auth macro create --file auth/sso_login.yaml")
					return
				}
				fmt.Printf("Auth macros (%d):\n", len(list))
				for _, m := range list {
					fmt.Printf("  %s  %s  %s\n", m["id"][:8], m["name"], m["type"])
				}
			})
			return nil
		},
	}
}

func authMacroShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show auth macro details",
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
			id, cfg, yamlContent, err := authmacro.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{"id": id, "config": cfg, "yaml": yamlContent}, func() {
				fmt.Printf("Macro: %s (%s) — %s\n", cfg.Name, id, cfg.Type)
				fmt.Printf("  Start URL: %s\n", cfg.StartURL)
				fmt.Printf("  Steps: %d\n", len(cfg.Steps))
				for i, s := range cfg.Steps {
					fmt.Printf("    %d. %s\n", i+1, s.Action)
				}
			})
			return nil
		},
	}
}

func authMacroRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run <name|id>",
		Short: "Run an auth macro",
		Example: `  agentburp auth macro run sso_login --json
  agentburp auth macro run sso_login --dry-run --json`,
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
			runner := authmacro.NewRunner(db, proj.ID)
			res, err := runner.Run(context.Background(), args[0], flagDryRun)
			if err != nil {
				return err
			}
			output.PrintAuto(res, func() {
				fmt.Printf("✓ Macro %s executed\n", args[0])
				for k, v := range res {
					fmt.Printf("  %s: %v\n", k, v)
				}
			})
			return nil
		},
	}
}

func authMacroDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete an auth macro",
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
			if flagDryRun {
				output.DryRun(map[string]interface{}{"would_delete": args[0]})
				return nil
			}
			if err := authmacro.NewStore(db, proj.ID).Delete(args[0]); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Auth macro %q deleted", args[0]), nil)
			return nil
		},
	}
}

// auth group extension: add macro subcommand under auth
func newAuthMacroGroupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Auth (extended)"}
	return cmd
}
