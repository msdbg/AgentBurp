package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/transport"
	"github.com/spf13/cobra"
)

func newTransportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transport",
		Short: "Manage transport profiles (real-world hardening)",
		Long: `Transport profiles define HOW requests are sent to survive WAF/CDN/anti-bot defenses.

Types:
  raw-http            Standard Go net/http (lab, simple APIs)
  fast-http           High-throughput tuned client
  browser-session     Uses cookies/session from real browser session
  browser-fetch       Executes request inside real browser (fetch/XHR)
  external-transport  Adapter for custom TLS / proxy chains (optional)`,
	}
	cmd.AddCommand(
		transportListCmd(),
		transportCreateCmd(),
		transportShowCmd(),
		transportDeleteCmd(),
	)
	return cmd
}

func transportListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List transport profiles",
		Example: `  agentburp transport list --json`,
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
			store := transport.NewStore(db, proj.ID)
			list, err := store.List()
			if err != nil {
				return err
			}
			if list == nil {
				list = []*transport.Profile{}
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No transport profiles. Create one: agentburp transport create --name raw --type raw-http")
					return
				}
				fmt.Printf("Transport profiles (%d):\n", len(list))
				for _, p := range list {
					fmt.Printf("  %s  %-18s  %s\n", core.ShortID(p.ID), p.Name, p.Type)
				}
			})
			return nil
		},
	}
}

func transportCreateCmd() *cobra.Command {
	var (
		name   string
		typ    string
		config string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a transport profile",
		Example: `  agentburp transport create --name raw --type raw-http --json
  agentburp transport create --name browser --type browser-session --json
  agentburp transport create --name fetch --type browser-fetch --json
  agentburp transport create --name custom --type external-transport --config '{"command":"./adapter"}'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || typ == "" {
				return fmt.Errorf("--name and --type are required (types: raw-http, fast-http, browser-session, browser-fetch, external-transport)")
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
					"name": name, "type": typ, "config": config,
					"note": "Would create transport profile",
				})
				return nil
			}
			store := transport.NewStore(db, proj.ID)
			profile, err := store.Create(name, transport.Type(typ), config)
			if err != nil {
				return err
			}
			output.PrintAuto(profile, func() {
				fmt.Printf("✓ Transport profile created: %s (%s)\n", profile.Name, profile.Type)
				fmt.Printf("  ID: %s\n", profile.ID)
				fmt.Printf("  Use: agentburp repeater send <rreq_id> --transport %s\n", profile.Name)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "profile name (required)")
	cmd.Flags().StringVar(&typ, "type", "", "transport type: raw-http|fast-http|browser-session|browser-fetch|external-transport")
	cmd.Flags().StringVar(&config, "config", "{}", "JSON config for transport (optional)")
	return cmd
}

func transportShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show transport profile details",
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
			store := transport.NewStore(db, proj.ID)
			p, err := store.Resolve(args[0])
			if err != nil {
				return err
			}
			var cfg json.RawMessage = p.Config
			output.PrintAuto(map[string]interface{}{
				"id": p.ID, "name": p.Name, "type": p.Type, "config": cfg, "created_at": p.CreatedAt,
			}, func() {
				fmt.Printf("Transport: %s (%s)\n", p.Name, p.Type)
				fmt.Printf("  ID: %s\n  Created: %s\n  Config: %s\n", p.ID, p.CreatedAt, string(p.Config))
			})
			return nil
		},
	}
}

func transportDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a transport profile",
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
			store := transport.NewStore(db, proj.ID)
			if err := store.Delete(args[0]); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Transport profile %q deleted", args[0]), nil)
			return nil
		},
	}
}
