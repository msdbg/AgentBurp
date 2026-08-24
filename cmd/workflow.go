package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/msdbg/AgentBurp/internal/workflow"
	"github.com/spf13/cobra"
)

func newWorkflowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow",
		Short: "Stateful workflow engine for business logic testing",
		Long: `Workflows are YAML sequences that build state before testing.

Example workflow (checkout.yaml):
  name: checkout_state
  steps:
    - name: create_cart
      request: { method: POST, url: https://app.example.com/api/cart }
      extract: { cart_id: $.cart.id }
    - name: add_item
      request: { method: POST, url: https://app.example.com/api/cart/{{cart_id}}/items, json: {item_id:1001} }

State is extracted via $.json.path or header:HeaderName and interpolated via {{var}}.`,
	}
	cmd.AddCommand(
		workflowCreateCmd(),
		workflowListCmd(),
		workflowShowCmd(),
		workflowRunCmd(),
		workflowDeleteCmd(),
	)
	return cmd
}

func workflowCreateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create workflow from YAML",
		Example: `  agentburp workflow create --file workflows/checkout.yaml --json`,
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
				cfg, err := workflow.ParseYAML(data)
				if err != nil {
					return fmt.Errorf("invalid workflow yaml: %w", err)
				}
				output.DryRun(map[string]interface{}{"file": file, "name": cfg.Name, "steps": len(cfg.Steps), "would_create": true, "size": len(data)})
				return nil
			}
			store := workflow.NewStore(db, proj.ID)
			id, err := store.Create("", string(data))
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"id": id, "file": file}, func() {
				fmt.Printf("✓ Workflow created: %s\n", id)
				fmt.Printf("  Run: agentburp workflow run %s --json\n", id)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "YAML file (required)")
	return cmd
}

func workflowListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List workflows",
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
			list, err := workflow.NewStore(db, proj.ID).List()
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No workflows. Create one: agentburp workflow create --file workflows/checkout.yaml")
					return
				}
				fmt.Printf("Workflows (%d):\n", len(list))
				for _, w := range list {
					fmt.Printf("  %s  %s  %s\n", core.ShortID(w["id"]), w["name"], w["created_at"])
				}
			})
			return nil
		},
	}
}

func workflowShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show workflow details",
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
			id, yamlContent, cfg, err := workflow.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{"id": id, "name": cfg.Name, "steps": len(cfg.Steps), "config": cfg, "yaml": yamlContent}, func() {
				fmt.Printf("Workflow: %s (%s) — %d steps\n", cfg.Name, core.ShortID(id), len(cfg.Steps))
				for i, s := range cfg.Steps {
					fmt.Printf("  %d. %s: %s %s\n", i+1, s.Name, s.Request.Method, s.Request.URL)
					if len(s.Extract) > 0 {
						fmt.Printf("     extract: %v\n", s.Extract)
					}
				}
			})
			return nil
		},
	}
}

func workflowRunCmd() *cobra.Command {
	var timeout int
	cmd := &cobra.Command{
		Use:   "run <name|id>",
		Short: "Run a workflow to build state",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp workflow run checkout_state --json
  agentburp workflow run wf_abc123 --dry-run --json`,
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
			id, _, cfg, err := workflow.NewStore(db, proj.ID).Get(args[0])
			if err != nil {
				return err
			}
			if flagDryRun {
				output.DryRun(map[string]interface{}{"workflow": cfg.Name, "id": id, "steps": len(cfg.Steps), "would_execute": cfg.Steps})
				return nil
			}
			runner := workflow.NewRunner(db, proj.ID, id, cfg)
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}
			fmt.Printf("Running workflow %s (%d steps)...\n", cfg.Name, len(cfg.Steps))
			start := time.Now()
			state, err := runner.Run(ctx, false)
			if err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{
				"workflow_id": id, "name": cfg.Name, "state": state, "elapsed": time.Since(start).String(),
			}, func() {
				fmt.Printf("✓ Workflow %s done in %s\n", cfg.Name, time.Since(start).Round(time.Millisecond))
				if len(state) > 0 {
					fmt.Printf("State:\n")
					for k, v := range state {
						val := v
						if len(val) > 100 {
							val = val[:97] + "..."
						}
						fmt.Printf("  %s = %s\n", k, val)
					}
				}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&timeout, "timeout", 60, "timeout seconds")
	return cmd
}

func workflowDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a workflow",
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
			if err := workflow.NewStore(db, proj.ID).Delete(args[0]); err != nil {
				return err
			}
			output.Success(fmt.Sprintf("Workflow %q deleted", args[0]), nil)
			return nil
		},
	}
}
