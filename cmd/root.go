package cmd

import (
	"fmt"
	"os"

	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	flagJSON    bool
	flagProject string
	flagDryRun  bool
	flagNoColor bool
)

var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "agentburp",
	Short: "Agent-first web security testing engine",
	Long: `AgentBurp is an agent-first, CLI-native web application security testing engine.

It gives AI agents (and humans) direct CLI access to:
  • Proxy & HTTPS interception
  • HTTP history & endpoint map
  • Request repeater & composer
  • Fuzzer (Intruder replacement)
  • Crawler & headless browsing
  • Passive & active scanner
  • Findings with evidence
  • Structured JSON output for every command

All commands support --json for machine-readable output.
All mutating commands support --dry-run for safe preview.

Project: https://github.com/msdbg/AgentBurp`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		output.JSONMode = flagJSON
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if output.JSONMode {
			output.Err(err)
		} else {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "output as JSON (machine-readable mode for AI agents)")
	rootCmd.PersistentFlags().StringVarP(&flagProject, "project", "p", "", "project name or ID (overrides active project)")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "preview what would happen without executing")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable color output")

	viper.BindPFlag("json", rootCmd.PersistentFlags().Lookup("json"))
	viper.BindPFlag("project", rootCmd.PersistentFlags().Lookup("project"))

	rootCmd.AddCommand(
		newProjectCmd(),
		newProxyCmd(),
		newHistoryCmd(),
		newEndpointsCmd(),
		newScopeCmd(),
		newRepeaterCmd(),
		newFuzzCmd(),
		newCrawlCmd(),
		newAuthCmd(),
		newScanCmd(),
		newFindingsCmd(),
		newDecodeCmd(),
		newDiffCmd(),
		newSequencerCmd(),
		newImportCmd(),
		newReportCmd(),
		newNotesCmd(),
		newJobsCmd(),
		newLogsCmd(),
		newStatusCmd(),
		newVersionCmd(),
		newTransportCmd(),
		newBrowserCmd(),
		newPolicyCmd(),
		newWorkflowCmd(),
		newDetectionsCmd(),
		newAdaptCmd(),
		newProxyProfileCmd(),
		newSessionValidateCmd(),
		newRequestCmd(),
	)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the AgentBurp version",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.PrintAuto(map[string]string{
				"name":    "agentburp",
				"version": Version,
			}, func() {
				fmt.Printf("agentburp %s\n", Version)
			})
			return nil
		},
	}
}

func initConfig() {
	home, err := os.UserHomeDir()
	if err == nil {
		viper.AddConfigPath(home + "/.agentburp")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}
	viper.AutomaticEnv()
	viper.ReadInConfig()
}

func resolveProject() string {
	if flagProject != "" {
		return flagProject
	}
	if p := viper.GetString("active_project"); p != "" {
		return p
	}
	return ""
}

func requireProject() string {
	p := resolveProject()
	if p == "" {
		output.Err(fmt.Errorf("no project specified — use --project <name> or run: agentburp project open <name>"))
		os.Exit(1)
	}
	return p
}
