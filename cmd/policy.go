package cmd

import (
	"fmt"
	"os"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage rate limiting and backoff policies (production pacing)",
		Long: `Policies govern safe testing against real-world targets.

Controls: requests_per_second, max_concurrency, jitter, exponential backoff on 429/403.

Example YAML:
  name: careful_production
  rate_limit:
    requests_per_second: 2
    max_concurrency: 1
    jitter_ms: 500
  backoff:
    on_status: [429, 403]
    initial_seconds: 30
    multiplier: 2
    max_seconds: 600`,
	}
	cmd.AddCommand(
		policyCreateCmd(),
		policyListCmd(),
		policyShowCmd(),
		policyDeleteCmd(),
		policyUseCmd(),
	)
	return cmd
}

func policyCreateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create policy from YAML file",
		Example: `  agentburp policy create --file policies/careful.yaml --json`,
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
				return fmt.Errorf("read file %q: %w", file, err)
			}
			if flagDryRun {
				cfg, err := policy.ParseYAML(data)
				if err != nil {
					return err
				}
				output.DryRun(cfg)
				return nil
			}

			cfg, _ := policy.ParseYAML(data)
			name := ""
			if cfg != nil {
				name = cfg.Name
			}
			if name == "" {
				name = file
			}
			createdCfg, id, err := policy.NewStore(db, proj.ID).Create(name, string(data))
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{"id": id, "name": createdCfg.Name, "config": createdCfg}, func() {
				fmt.Printf("✓ Policy created: %s (%s)\n", createdCfg.Name, id)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "YAML file path (required)")
	return cmd
}

func policyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List policies",
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
			list, err := policy.NewStore(db, proj.ID).List()
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No policies. Create one: agentburp policy create --file policies/careful.yaml")
					return
				}
				fmt.Printf("Policies (%d):\n", len(list))
				for _, p := range list {
					fmt.Printf("  %s  %s  %s\n", core.ShortID(p["id"]), p["name"], p["created_at"])
				}
			})
			return nil
		},
	}
}

func policyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show policy details",
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
			cfg, id, err := policy.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{"id": id, "name": cfg.Name, "config": cfg}, func() {
				fmt.Printf("Policy: %s (%s)\n", cfg.Name, id)
				fmt.Printf("  RPS: %d  Concurrency: %d  Jitter: %dms\n", cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.MaxConcurrency, cfg.RateLimit.JitterMs)
				fmt.Printf("  Backoff on: %v  initial=%ds max=%ds\n", cfg.Backoff.OnStatus, cfg.Backoff.InitialSeconds, cfg.Backoff.MaxSeconds)
			})
			return nil
		},
	}
}

func policyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a policy",
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
			if err := policy.NewStore(db, proj.ID).Delete(args[0]); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Policy %q deleted", args[0]), nil)
			return nil
		},
	}
}

func policyUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "use <name|id>",
		Short:   "Set active policy for project (applies to fuzz/crawl/scan)",
		Args:    cobra.ExactArgs(1),
		Example: `  agentburp policy use careful_production --json`,
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
			cfg, id, err := policy.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}

			currentCfg, _ := core.LoadConfig(projectName)

			db.Conn().Exec(`INSERT INTO events (id, project_id, timestamp, actor, action, object_type, object_id, result, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				core.NewID("evt"), proj.ID, core.TimestampNow(), "agent", "policy.use", "policy", id, "ok", fmt.Sprintf(`{"name":%q}`, cfg.Name))

			_ = currentCfg
			output.PrintAuto(map[string]interface{}{"active_policy": cfg.Name, "id": id}, func() {
				fmt.Printf("✓ Active policy: %s (%s)\n", cfg.Name, core.ShortID(id))
				fmt.Printf("  Apply to jobs: agentburp fuzz run <job> --policy %s\n", cfg.Name)
			})
			return nil
		},
	}
}
