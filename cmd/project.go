package cmd

import (
	"fmt"
	"os"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newProjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Manage AgentBurp projects",
		Long: `Projects are the top-level container for all AgentBurp state.
Each project has its own SQLite database, CA certificate, and configuration.
Projects are stored at: ~/.agentburp/projects/<name>/`,
	}
	cmd.AddCommand(
		projectCreateCmd(),
		projectOpenCmd(),
		projectListCmd(),
		projectDeleteCmd(),
	)
	return cmd
}

func projectCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new project",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp project create webapp-pentest
  agentburp project create webapp-pentest --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dbPath := core.ProjectDBPath(name)

			if err := os.MkdirAll(core.ProjectDir(name), 0o755); err != nil {
				return fmt.Errorf("create project dir: %w", err)
			}

			db, err := core.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			store := core.NewProjectStore(db)
			proj, err := store.Create(name)
			if err != nil {
				return err
			}

			if err := core.SaveConfig(name, core.DefaultConfig()); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			viper.Set("active_project", name)
			if err := viper.WriteConfig(); err != nil {

				home, _ := os.UserHomeDir()
				cfgPath := home + "/.agentburp/config.yaml"
				os.MkdirAll(home+"/.agentburp", 0o755)
				viper.SetConfigFile(cfgPath)
				viper.WriteConfig()
			}

			output.PrintAuto(proj, func() {
				fmt.Printf("✓ Project created: %s\n", proj.Name)
				fmt.Printf("  ID:      %s\n", proj.ID)
				fmt.Printf("  Path:    %s\n", core.ProjectDir(name))
				fmt.Printf("  DB:      %s\n", dbPath)
				fmt.Printf("  Active:  yes\n\n")
				fmt.Printf("Next steps:\n")
				fmt.Printf("  agentburp scope add <target-url> --include\n")
				fmt.Printf("  agentburp proxy start\n")
			})
			return nil
		},
	}
}

func projectOpenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "open <name>",
		Short: "Set a project as the active project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dbPath := core.ProjectDBPath(name)

			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				return fmt.Errorf("project %q not found at %s", name, core.ProjectDir(name))
			}

			db, err := core.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			store := core.NewProjectStore(db)
			proj, err := store.Get(name)
			if err != nil {
				return err
			}

			viper.Set("active_project", name)
			home, _ := os.UserHomeDir()
			cfgPath := home + "/.agentburp/config.yaml"
			os.MkdirAll(home+"/.agentburp", 0o755)
			viper.SetConfigFile(cfgPath)
			viper.WriteConfig()

			output.PrintAuto(proj, func() {
				fmt.Printf("✓ Active project: %s (%s)\n", proj.Name, proj.ID)
			})
			return nil
		},
	}
}

func projectListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			projectsDir := core.DefaultProjectsDir()
			entries, err := os.ReadDir(projectsDir)
			if err != nil {
				if os.IsNotExist(err) {
					output.PrintAuto([]interface{}{}, func() {
						fmt.Println("No projects found. Create one with: agentburp project create <name>")
					})
					return nil
				}
				return err
			}

			type ProjectSummary struct {
				Name   string `json:"name"`
				Path   string `json:"path"`
				Active bool   `json:"active"`
			}

			active := resolveProject()
			var summaries []ProjectSummary
			for _, e := range entries {
				if e.IsDir() {
					dbPath := core.ProjectDBPath(e.Name())
					if _, err := os.Stat(dbPath); err == nil {
						summaries = append(summaries, ProjectSummary{
							Name:   e.Name(),
							Path:   core.ProjectDir(e.Name()),
							Active: e.Name() == active,
						})
					}
				}
			}

			output.PrintAuto(summaries, func() {
				if len(summaries) == 0 {
					fmt.Println("No projects found.")
					return
				}
				headers := []string{"NAME", "ACTIVE", "PATH"}
				var rows [][]string
				for _, s := range summaries {
					marker := ""
					if s.Active {
						marker = "●"
					}
					rows = append(rows, []string{s.Name, marker, s.Path})
				}
				output.PrintTable(headers, rows)
			})
			return nil
		},
	}
}

func projectDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a project (moves to trash, use --force to permanently delete)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dir := core.ProjectDir(name)

			if _, err := os.Stat(dir); os.IsNotExist(err) {
				return fmt.Errorf("project %q not found", name)
			}

			if force {
				if err := os.RemoveAll(dir); err != nil {
					return fmt.Errorf("delete project: %w", err)
				}
				output.Success(fmt.Sprintf("Project %q permanently deleted", name), nil)
			} else {

				trash := dir + ".deleted"
				if err := os.Rename(dir, trash); err != nil {
					return fmt.Errorf("move to trash: %w", err)
				}
				output.PrintAuto(map[string]string{
					"status": "deleted",
					"name":   name,
					"path":   trash,
					"note":   "use --force to permanently delete",
				}, func() {
					fmt.Printf("✓ Project %q moved to: %s\n", name, trash)
					fmt.Printf("  Use --force to permanently delete.\n")
				})
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "permanently delete (cannot be undone)")
	return cmd
}
