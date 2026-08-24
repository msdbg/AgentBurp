package cmd

import (
	"fmt"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/proxyprofile"
	"github.com/spf13/cobra"
)

func newProxyProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-profile",
		Short: "Manage proxy profiles for authorized engagements",
		Long: `Proxy profiles control routing for authorized engagements.

Types: http, https, socks5, upstream, authorized_residential

Rotation is DISABLED by default and requires explicit --allow-rotation with policy approval.
This is a safety guard for professional use.`,
	}
	cmd.AddCommand(
		proxyProfileCreateCmd(),
		proxyProfileListCmd(),
		proxyProfileShowCmd(),
		proxyProfileCheckCmd(),
		proxyProfileDeleteCmd(),
		proxyProfileUseCmd(),
	)
	return cmd
}

func proxyProfileCreateCmd() *cobra.Command {
	var (
		name     string
		typ      string
		urlStr   string
		rotation string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a proxy profile",
		Example: `  agentburp proxy-profile create --name local --type http --url http://127.0.0.1:8080 --json
  agentburp proxy-profile create --name residential --type socks5 --url socks5://proxy.example:1080 --json`,
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
				output.DryRun(map[string]interface{}{"name": name, "type": typ, "url": urlStr})
				return nil
			}
			store := proxyprofile.NewStore(db, proj.ID)
			id, err := store.Create(name, typ, urlStr, rotation)
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"id": id, "name": name, "type": typ, "url": urlStr}, func() {
				fmt.Printf("✓ Proxy profile created: %s (%s) -> %s\n", name, typ, urlStr)
				fmt.Printf("  ID: %s\n", id)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "profile name (required)")
	cmd.Flags().StringVar(&typ, "type", "", "proxy type: http|https|socks5|upstream|authorized_residential (required)")
	cmd.Flags().StringVar(&urlStr, "url", "", "proxy URL (required, e.g. http://127.0.0.1:8080)")
	cmd.Flags().StringVar(&rotation, "rotation-policy", "disabled", "rotation policy: disabled|allow_rotation")
	return cmd
}

func proxyProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List proxy profiles",
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
			list, err := proxyprofile.NewStore(db, proj.ID).List()
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No proxy profiles. Create one: agentburp proxy-profile create --name local --type http --url http://127.0.0.1:8080")
					return
				}
				fmt.Printf("Proxy profiles (%d):\n", len(list))
				for _, p := range list {
					fmt.Printf("  %s  %-18s  %-12s  %s\n", p["id"][:8], p["name"], p["type"], p["url"])
				}
			})
			return nil
		},
	}
}

func proxyProfileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show proxy profile",
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
			p, err := proxyprofile.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(p, func() {
				fmt.Printf("Proxy: %s (%s) -> %s\n", p["name"], p["type"], p["url"])
				fmt.Printf("  Rotation: %s\n", p["rotation_policy"])
			})
			return nil
		},
	}
}

func proxyProfileCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <name|id>",
		Short: "Check proxy profile health",
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
			res, err := proxyprofile.NewStore(db, proj.ID).Check(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(res, func() {
				fmt.Printf("Proxy %s: %s -> %s (%s)\n", res["name"], res["type"], res["url"], res["status"])
			})
			return nil
		},
	}
}

func proxyProfileDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a proxy profile",
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
			if err := proxyprofile.NewStore(db, proj.ID).Delete(args[0]); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Proxy profile %q deleted", args[0]), nil)
			return nil
		},
	}
}

func proxyProfileUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <name|id>",
		Short: "Set active proxy profile for project",
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
			p, err := proxyprofile.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}
			db.Conn().Exec(`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				core.NewID("evt"), proj.ID, core.TimestampNow(), "agent", "proxy_profile.use", "proxy_profile", p["id"], "ok", fmt.Sprintf(`{"name":%q}`, p["name"]))
			output.PrintAuto(map[string]string{"active_proxy": p["name"], "id": p["id"], "url": p["url"]}, func() {
				fmt.Printf("✓ Active proxy: %s -> %s\n", p["name"], p["url"])
			})
			return nil
		},
	}
}
