package cmd

import (
	"fmt"

	"github.com/msdbg/AgentBurp/internal/adaptation"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newDetectionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detections",
		Short: "WAF / Anti-bot detection dashboard",
		Long:  `Summarizes blocks, challenges, and adaptations for the agent operator.`,
	}
	cmd.AddCommand(
		detectionsListCmd(),
		detectionsSummaryCmd(),
	)
	return cmd
}

func detectionsListCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List detections",
		Example: `  agentburp detections list --json
  agentburp detections list --limit 20 --json`,
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
			engine := adaptation.NewEngine(db, proj.ID)
			list, err := engine.ListDetections(limit)
			if err != nil {
				return err
			}
			output.PrintAuto(list, func() {
				if len(list) == 0 {
					fmt.Println("No detections yet.")
					return
				}
				fmt.Printf("Detections (%d):\n", len(list))
				for _, d := range list {
					fmt.Printf("  %s  %-22s  %s  %s\n", d.ID[:8], d.Type, d.Confidence, d.CreatedAt)
				}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "max results")
	return cmd
}

func detectionsSummaryCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "summary",
		Short:   "Show detection summary with recommendations",
		Example: `  agentburp detections summary --json`,
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
			engine := adaptation.NewEngine(db, proj.ID)
			summary, err := engine.Summary()
			if err != nil {
				return err
			}
			// Wrap for JSON schema expected in plan
			wrapped := map[string]interface{}{
				"object": "detection_summary",
				"data":   summary,
			}
			output.PrintAuto(wrapped, func() {
				fmt.Printf("Detection summary:\n")
				if counts, ok := summary["counts"].(map[string]int); ok {
					for k, v := range counts {
						fmt.Printf("  %-22s %d\n", k+":", v)
					}
				}
				fmt.Printf("\n  Recommended transport: %v\n", summary["recommended_transport"])
				fmt.Printf("  Recommended policy:    %v\n", summary["recommended_policy"])
			})
			return nil
		},
	}
}

func newAdaptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "adapt",
		Short: "Adaptation engine status and rules",
	}
	cmd.AddCommand(
		adaptStatusCmd(),
		adaptRulesListCmd(),
	)
	return cmd
}

func adaptStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Short:   "Show adaptation status",
		Example: `  agentburp adapt status --json`,
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
			engine := adaptation.NewEngine(db, proj.ID)
			summary, _ := engine.Summary()
			adaps, _ := engine.ListAdaptations(20)
			dets, _ := engine.ListDetections(20)
			result := map[string]interface{}{
				"project_id":         proj.ID,
				"detections":         len(dets),
				"adaptations":        len(adaps),
				"summary":            summary,
				"recent_detections":  dets,
				"recent_adaptations": adaps,
			}
			output.PrintAuto(result, func() {
				fmt.Printf("Adaptation Engine — project %s\n", proj.Name)
				fmt.Printf("  Detections: %d  Adaptations: %d\n", len(dets), len(adaps))
				if len(dets) > 0 {
					fmt.Printf("\nRecent detections:\n")
					for _, d := range dets[:min(5, len(dets))] {
						fmt.Printf("  %s  %s\n", d.Type, d.CreatedAt)
					}
				}
			})
			return nil
		},
	}
}

func adaptRulesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List adaptation rules (detection -> action mappings)",
		RunE: func(cmd *cobra.Command, args []string) error {
			rules := []map[string]string{
				{"detection": "rate_limited", "action": "slow_down + backoff", "confidence": "high"},
				{"detection": "ip_blocked", "action": "abort_or_switch_proxy (requires explicit allow-rotation)", "confidence": "high"},
				{"detection": "session_expired / auth_required (401)", "action": "run_auth_macro + retry once", "confidence": "high"},
				{"detection": "captcha_required", "action": "pause_for_human (headed browser)", "confidence": "high"},
				{"detection": "js_challenge", "action": "switch_to_browser_session", "confidence": "medium"},
				{"detection": "waf_block (403/406)", "action": "switch_transport_or_backoff", "confidence": "medium"},
				{"detection": "signature_invalid", "action": "regenerate_signature_via_js_bridge or browser-fetch", "confidence": "medium"},
				{"detection": "csrf_token_expired", "action": "refresh_csrf_token / rerun workflow", "confidence": "high"},
			}
			output.PrintAuto(rules, func() {
				fmt.Printf("Adaptation rules:\n")
				for _, r := range rules {
					fmt.Printf("  %-36s -> %s\n", r["detection"], r["action"])
				}
			})
			return nil
		},
	}
}

func init() {

}
