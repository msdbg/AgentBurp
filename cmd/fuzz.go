package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/fuzzer"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newFuzzCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Payload-based fuzzing engine (Intruder replacement)",
		Long: `The fuzzer sends a base request with positions replaced by payloads.

Attack types (matching Burp Intruder):
  sniper        — single payload set, one position at a time
  battering-ram — single payload set, all positions simultaneously
  pitchfork     — multiple payload sets, parallel iteration
  cluster-bomb  — multiple payload sets, cartesian product

Workflow:
  1. agentburp fuzz create --request <req_id>
  2. agentburp fuzz position add <job_id> <location>
  3. agentburp fuzz payload wordlist <job_id> --file payloads.txt
  4. agentburp fuzz run <job_id> --dry-run   # validate first
  5. agentburp fuzz run <job_id>
  6. agentburp fuzz results <job_id> --anomalies-only --json`,
	}
	cmd.AddCommand(
		fuzzCreateCmd(),
		fuzzPositionCmd(),
		fuzzPayloadCmd(),
		fuzzAttackTypeCmd(),
		fuzzFilterCmd(),
		fuzzRunCmd(),
		fuzzStopCmd(),
		fuzzResultsCmd(),
	)
	return cmd
}

// fuzzJobConfig loads a fuzz job's config as a mutable map.
func fuzzJobConfig(db *core.DB, jobID string) (map[string]interface{}, error) {
	return core.NewJobStore(db).GetConfig(jobID)
}

func fuzzCreateCmd() *cobra.Command {
	var reqID string
	cmd := &cobra.Command{
		Use: "create", Short: "Create a fuzz job from a request",
		Example: "  agentburp fuzz create --request req_abc123 --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			if reqID == "" {
				return fmt.Errorf("--request is required")
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

			var exists int
			db.Conn().QueryRow(`SELECT 1 FROM requests WHERE id = ?`, reqID).Scan(&exists)
			if exists != 1 {
				return fmt.Errorf("request %s not found in history", reqID)
			}

			jobID, err := core.NewJobStore(db).Create(proj.ID, "fuzz", map[string]interface{}{
				"request_id":  reqID,
				"attack_type": "sniper",
				"positions":   []string{},
				"set_indexes": []int{},
				"payloads":    []interface{}{},
				"filters":     map[string]interface{}{},
			})
			if err != nil {
				return err
			}

			output.PrintAuto(map[string]string{
				"job_id":     jobID,
				"request_id": reqID,
				"status":     "created",
			}, func() {
				fmt.Printf("✓ Fuzz job created: %s\n", jobID)
				fmt.Printf("  Base request: %s\n\n", reqID)
				fmt.Printf("Next:\n")
				fmt.Printf("  agentburp fuzz position add %s body.username\n", jobID)
				fmt.Printf("  agentburp fuzz payload wordlist %s --file wordlist.txt\n", jobID)
				fmt.Printf("  agentburp fuzz run %s --dry-run\n", jobID)
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&reqID, "request", "", "base request ID (required)")
	return cmd
}

func fuzzPositionCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "position", Short: "Manage fuzz payload positions"}

	addCmd := &cobra.Command{
		Use: "add <job_id> <location>", Short: "Add a payload position",
		Args: cobra.ExactArgs(2),
		Example: `  agentburp fuzz position add job_abc123 body.username
  agentburp fuzz position add job_abc123 query.id
  agentburp fuzz position add job_abc123 header.X-User-Id
  agentburp fuzz position add job_abc123 path.userId`,
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID, location := args[0], args[1]
			if _, err := fuzzer.ParsePosition(location); err != nil {
				return err
			}
			setIdx, _ := cmd.Flags().GetInt("set")

			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			store := core.NewJobStore(db)
			job, err := store.Get(jobID)
			if err != nil {
				return err
			}
			if job.Type != "fuzz" {
				return fmt.Errorf("job %s is not a fuzz job", jobID)
			}
			cfg := job.Config

			positions, _ := cfg["positions"].([]interface{})
			locations := make([]string, 0, len(positions)+1)
			for _, p := range positions {
				locations = append(locations, fmt.Sprint(p))
			}
			for _, l := range locations {
				if l == location {
					return fmt.Errorf("position %q already configured", location)
				}
			}
			locations = append(locations, location)

			setIndexes, _ := cfg["set_indexes"].([]interface{})
			sis := make([]int, 0, len(setIndexes)+1)
			for _, s := range setIndexes {
				n, _ := s.(float64)
				sis = append(sis, int(n))
			}
			sis = append(sis, setIdx)

			cfg["positions"] = locations
			cfg["set_indexes"] = sis
			if err := store.SetConfig(jobID, cfg); err != nil {
				return err
			}
			db.Conn().Exec(`
				INSERT INTO fuzz_positions (id, job_id, location, set_index)
				VALUES (?, ?, ?, ?)`,
				core.NewID("fp"), jobID, location, setIdx,
			)

			output.PrintAuto(map[string]interface{}{
				"job_id":   jobID,
				"location": location,
				"set":      setIdx,
			}, func() {
				fmt.Printf("✓ Position added: %s (payload set %d)\n", location, setIdx)
				fmt.Printf("  Job: %s\n", jobID)
			})
			return nil
		},
	}
	addCmd.Flags().Int("set", 0, "payload set index this position uses")

	listCmd := &cobra.Command{
		Use: "list <job_id>", Short: "List payload positions for a job",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			rows, err := db.Conn().Query(`
				SELECT id, location, set_index FROM fuzz_positions WHERE job_id = ? ORDER BY rowid`, args[0])
			if err != nil {
				return err
			}
			defer rows.Close()
			type posRow struct {
				ID       string `json:"id"`
				Location string `json:"location"`
				SetIndex int    `json:"set_index"`
			}
			var out []posRow
			for rows.Next() {
				var p posRow
				if err := rows.Scan(&p.ID, &p.Location, &p.SetIndex); err != nil {
					return err
				}
				out = append(out, p)
			}
			output.PrintAuto(out, func() {
				if len(out) == 0 {
					fmt.Printf("Positions for job %s: (none configured)\n", args[0])
					return
				}
				fmt.Printf("Positions for job %s:\n", args[0])
				for _, p := range out {
					fmt.Printf("  %s  (set %d)\n", p.Location, p.SetIndex)
				}
			})
			return nil
		},
	}
	cmd.AddCommand(addCmd, listCmd)
	return cmd
}

func addPayloadSet(db *core.DB, store *core.JobStore, jobID, setName string, values []string) (int, error) {
	cfg, err := store.GetConfig(jobID)
	if err != nil {
		return 0, err
	}
	rawPayloads, _ := cfg["payloads"].([]interface{})
	payloads := make([]map[string]interface{}, 0, len(rawPayloads)+1)
	for _, p := range rawPayloads {
		if m, ok := p.(map[string]interface{}); ok {
			payloads = append(payloads, m)
		}
	}
	idx := len(payloads)
	payloads = append(payloads, map[string]interface{}{
		"name":   setName,
		"values": values,
	})
	cfg["payloads"] = payloads
	if err := store.SetConfig(jobID, cfg); err != nil {
		return 0, err
	}
	return idx, nil
}

func fuzzPayloadCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "payload", Short: "Configure payload sources"}

	wordlistCmd := &cobra.Command{
		Use: "wordlist <job_id>", Short: "Use a wordlist file as payload source",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, _ := cmd.Flags().GetString("file")
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			values, err := fuzzer.Wordlist(file)
			if err != nil {
				return err
			}
			return persistPayloadSet(args[0], "wordlist:"+file, values, file)
		},
	}
	wordlistCmd.Flags().String("file", "", "wordlist file path (required)")

	numbersCmd := &cobra.Command{
		Use: "numbers <job_id>", Short: "Generate numeric payloads",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, _ := cmd.Flags().GetInt("from")
			to, _ := cmd.Flags().GetInt("to")
			step, _ := cmd.Flags().GetInt("step")
			values, err := fuzzer.Numbers(from, to, step)
			if err != nil {
				return err
			}
			return persistPayloadSet(args[0], fmt.Sprintf("numbers:%d-%d", from, to), values, "")
		},
	}
	numbersCmd.Flags().Int("from", 1, "start of range")
	numbersCmd.Flags().Int("to", 100, "end of range")
	numbersCmd.Flags().Int("step", 1, "step size")

	mutationsCmd := &cobra.Command{
		Use: "mutations <job_id>", Short: "Use boundary/mutation payloads",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return persistPayloadSet(args[0], "mutations:builtin", fuzzer.Mutations(), "")
		},
	}
	cmd.AddCommand(wordlistCmd, numbersCmd, mutationsCmd)
	return cmd
}

func persistPayloadSet(jobID, setName string, values []string, note string) error {
	projectName := requireProject()
	db, err := openProjectDB(projectName)
	if err != nil {
		return err
	}
	defer db.Close()
	idx, err := addPayloadSet(db, core.NewJobStore(db), jobID, setName, values)
	if err != nil {
		return err
	}
	output.PrintAuto(map[string]interface{}{
		"job_id":  jobID,
		"set":     idx,
		"name":    setName,
		"count":   len(values),
		"preview": valuesPreview(values),
	}, func() {
		fmt.Printf("✓ Payload set %d configured: %s (%d payloads)\n", idx, setName, len(values))
		if note != "" {
			fmt.Printf("  Source: %s\n", note)
		}
		fmt.Printf("  First: %s\n", valuesPreview(values))
	})
	return nil
}

func valuesPreview(values []string) []string {
	if len(values) > 5 {
		return append(values[:5], fmt.Sprintf("… %d more", len(values)-5))
	}
	return values
}

func fuzzAttackTypeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attack-type <job_id> <type>",
		Short: "Set the attack type: sniper|battering-ram|pitchfork|cluster-bomb",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID, at := args[0], args[1]
			if _, err := fuzzer.ParseAttackType(at); err != nil {
				return err
			}
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			store := core.NewJobStore(db)
			cfg, err := store.GetConfig(jobID)
			if err != nil {
				return err
			}
			cfg["attack_type"] = at
			if err := store.SetConfig(jobID, cfg); err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"job_id": jobID, "attack_type": at}, func() {
				fmt.Printf("✓ Attack type set to %q for job %s\n", at, jobID)
			})
			return nil
		},
	}
}

func fuzzFilterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "filter", Short: "Add response filters to a fuzz job"}
	addCmd := &cobra.Command{
		Use: "add <job_id>", Short: "Add a filter condition",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID := args[0]
			status, _ := cmd.Flags().GetInt("status")
			lengthGT, _ := cmd.Flags().GetInt("length-gt")
			lengthLT, _ := cmd.Flags().GetInt("length-lt")
			regex, _ := cmd.Flags().GetString("regex")
			grep, _ := cmd.Flags().GetString("grep")

			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			store := core.NewJobStore(db)
			cfg, err := store.GetConfig(jobID)
			if err != nil {
				return err
			}
			filters, _ := cfg["filters"].(map[string]interface{})
			if filters == nil {
				filters = map[string]interface{}{}
			}
			if status != 0 {
				codes, _ := filters["status_codes"].([]interface{})
				filters["status_codes"] = append(codes, status)
			}
			if lengthGT > 0 {
				filters["length_gt"] = lengthGT
			}
			if lengthLT > 0 {
				filters["length_lt"] = lengthLT
			}
			if regex != "" {
				filters["regex"] = regex
			}
			if grep != "" {
				greps, _ := filters["grep"].([]interface{})
				filters["grep"] = append(greps, grep)
			}
			if status == 0 && lengthGT == 0 && lengthLT == 0 && regex == "" && grep == "" {
				return fmt.Errorf("no filter condition given — use --status, --length-gt, --length-lt, --regex, or --grep")
			}
			cfg["filters"] = filters
			if err := store.SetConfig(jobID, cfg); err != nil {
				return err
			}
			output.PrintAuto(map[string]interface{}{"job_id": jobID, "filters": filters}, func() {
				fmt.Printf("✓ Filters added to job %s\n", jobID)
				printFilters(filters)
			})
			return nil
		},
	}
	addCmd.Flags().Int("status", 0, "match status code")
	addCmd.Flags().Int("length-gt", 0, "match response length greater than N")
	addCmd.Flags().Int("length-lt", 0, "match response length less than N")
	addCmd.Flags().String("regex", "", "match response body regex")
	addCmd.Flags().String("grep", "", "grep for string in response")
	cmd.AddCommand(addCmd)
	return cmd
}

func printFilters(filters map[string]interface{}) {
	if codes, ok := filters["status_codes"].([]interface{}); ok && len(codes) > 0 {
		fmt.Printf("  status in: %v\n", codes)
	}
	if v, ok := filters["length_gt"].(float64); ok && v > 0 {
		fmt.Printf("  length > %d\n", int(v))
	}
	if v, ok := filters["length_lt"].(float64); ok && v > 0 {
		fmt.Printf("  length < %d\n", int(v))
	}
	if v, ok := filters["regex"].(string); ok && v != "" {
		fmt.Printf("  body regex: %s\n", v)
	}
	if greps, ok := filters["grep"].([]interface{}); ok && len(greps) > 0 {
		fmt.Printf("  body contains: %v\n", greps)
	}
}

func fuzzRunCmd() *cobra.Command {
	var (
		concurrency int
		rate        int
	)
	cmd := &cobra.Command{
		Use:   "run <job_id>",
		Short: "Execute a fuzz job",
		Args:  cobra.ExactArgs(1),
		Example: `  agentburp fuzz run job_abc123 --dry-run
  agentburp fuzz run job_abc123 --rate 10 --concurrency 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID := args[0]
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

			runner, err := fuzzer.NewRunner(db, proj, jobID, concurrency, rate)
			if err != nil {
				return err
			}
			planCount, err := runner.PlanCount()
			if err != nil {
				return err
			}

			if flagDryRun {
				output.DryRun(map[string]interface{}{
					"job_id":       jobID,
					"attack_type":  string(runner.AttackType()),
					"positions":    positionsToPlan(runner.Positions()),
					"payload_sets": len(runner.PayloadSets()),
					"would_send":   planCount,
					"rate":         rate,
					"concurrency":  concurrency,
					"scope_check":  "enforced",
					"session":      runner.SessionID(),
				})
				return nil
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				core.NewJobStore(db).SetStatus(jobID, "cancelled")
			}()

			fmt.Printf("Starting fuzz job %s — %s attack, %d requests (rate: %d/s, concurrency: %d)...\n",
				jobID, runner.AttackType(), planCount, rate, concurrency)
			start := time.Now()
			err = runner.Run(ctx)
			if err != nil {
				return err
			}
			job, _ := core.NewJobStore(db).Get(jobID)
			elapsed := time.Since(start).Round(time.Second)
			if job.Status == "cancelled" {
				fmt.Printf("Fuzz job %s cancelled after %s\n", jobID, elapsed)
				return nil
			}
			fmt.Printf("✓ Fuzz job %s finished in %s\n", jobID, elapsed)
			fmt.Printf("  Sent: %v | Anomalies: %v\n", job.ResultSummary["sent"], job.ResultSummary["anomalies"])
			fmt.Printf("\nView results: agentburp fuzz results %s --anomalies-only\n", jobID)
			return nil
		},
	}
	cmd.Flags().IntVar(&concurrency, "concurrency", 10, "number of concurrent goroutines")
	cmd.Flags().IntVar(&rate, "rate", 10, "max requests per second per host")
	return cmd
}

func positionsToPlan(positions []*fuzzer.Position) []string {
	out := make([]string, 0, len(positions))
	for _, p := range positions {
		out = append(out, p.Location)
	}
	return out
}

func fuzzStopCmd() *cobra.Command {
	return &cobra.Command{
		Use: "stop <job_id>", Short: "Stop a running fuzz job",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := core.NewJobStore(db).Cancel(args[0]); err != nil {
				return err
			}
			output.PrintAuto(map[string]string{"job_id": args[0], "status": "cancelled"}, func() {
				fmt.Printf("✓ Fuzz job %s cancelled\n", args[0])
			})
			return nil
		},
	}
}

func fuzzResultsCmd() *cobra.Command {
	var anomaliesOnly bool
	cmd := &cobra.Command{
		Use: "results <job_id>", Short: "Show fuzz job results",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID := args[0]
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			store := core.NewJobStore(db)
			job, err := store.Get(jobID)
			if err != nil {
				return err
			}

			rows, err := db.Conn().Query(`
				SELECT fr.id, fr.request_id, COALESCE(fr.response_id,''), fr.payload_json, fr.anomaly,
				       COALESCE(fr.anomaly_reason,''), COALESCE(r.status_code,0), COALESCE(r.length_bytes,0),
				       COALESCE(r.time_ms,0), fr.created_at
				FROM fuzz_results fr
				LEFT JOIN responses r ON r.id = fr.response_id
				WHERE fr.job_id = ? AND (? = 0 OR fr.anomaly = 1)
				ORDER BY fr.created_at`, jobID, boolIntFlag(anomaliesOnly))
			if err != nil {
				return err
			}
			defer rows.Close()

			type row struct {
				ID            string            `json:"id"`
				RequestID     string            `json:"request_id"`
				ResponseID    string            `json:"response_id,omitempty"`
				Payloads      map[string]string `json:"payloads"`
				Anomaly       bool              `json:"anomaly"`
				AnomalyReason string            `json:"anomaly_reason,omitempty"`
				Status        int               `json:"status_code"`
				Length        int               `json:"length_bytes"`
				TimeMS        int64             `json:"time_ms"`
				CreatedAt     string            `json:"created_at"`
			}
			var results []row
			for rows.Next() {
				var fr row
				var payloadJSON, reason string
				var anomaly int
				if err := rows.Scan(&fr.ID, &fr.RequestID, &fr.ResponseID, &payloadJSON, &anomaly,
					&reason, &fr.Status, &fr.Length, &fr.TimeMS, &fr.CreatedAt); err != nil {
					return err
				}
				fr.Anomaly = anomaly == 1
				fr.AnomalyReason = reason
				json.Unmarshal([]byte(payloadJSON), &fr.Payloads)
				results = append(results, fr)
			}

			anomalyCount := 0
			for _, r := range results {
				if r.Anomaly {
					anomalyCount++
				}
			}

			output.PrintAuto(map[string]interface{}{
				"job_id":         jobID,
				"status":         job.Status,
				"total":          len(results),
				"anomalies":      anomalyCount,
				"anomalies_only": anomaliesOnly,
				"results":        results,
			}, func() {
				fmt.Printf("Fuzz results for job %s (status: %s):\n", jobID, job.Status)
				if len(results) == 0 {
					fmt.Println("  (no results)")
					return
				}
				for _, fr := range results {
					marker := "  "
					if fr.Anomaly {
						marker = "! "
					}
					fmt.Printf("%s %s %s %d (%dB, %dms)%s\n", marker, fr.ID, fr.Payloads, fr.Status, fr.Length, fr.TimeMS, reasonSuffix(fr.Anomaly, fr.AnomalyReason))
				}
			})
			return nil
		},
	}
	cmd.Flags().BoolVar(&anomaliesOnly, "anomalies-only", false, "show only anomalous results")
	return cmd
}

func reasonSuffix(anomaly bool, reason string) string {
	if anomaly && reason != "" {
		return " [" + reason + "]"
	}
	return ""
}

func boolIntFlag(b bool) int {
	if b {
		return 1
	}
	return 0
}
