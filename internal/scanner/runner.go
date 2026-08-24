package scanner

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
)

// ScanSummary is the job result summary written to jobs.result_summary_json.
type ScanSummary struct {
	Mode           string         `json:"mode"`
	Scanned        int            `json:"scanned"`
	ProbesSent     int            `json:"probes_sent"`
	ProbesSkipped  int            `json:"probes_skipped"`
	SkippedReasons map[string]int `json:"skipped_reasons,omitempty"`
	NewFindings    int            `json:"new_findings"`
	TotalFindings  int            `json:"total_findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCheck        map[string]int `json:"by_check"`
	DurationMS     int64          `json:"duration_ms"`
	Note           string         `json:"note,omitempty"`
}

// RunPassive scans captured traffic (all exchanges or a single request)
// and stores findings. Runs synchronously and manages the job lifecycle.
func RunPassive(ctx context.Context, db *core.DB, proj *core.Project, jobID, reqID string) (*ScanSummary, error) {
	store := core.NewJobStore(db)
	if err := store.MarkRunning(jobID); err != nil {
		return nil, err
	}
	start := time.Now()

	exchanges, err := loadExchanges(db.Conn(), proj.ID, reqID)
	if err != nil {
		store.MarkFailed(jobID, err.Error())
		return nil, err
	}

	findings := NewFindingsStore(db, proj.ID)
	summary := &ScanSummary{
		Mode:           "passive",
		BySeverity:     map[string]int{},
		ByCheck:        map[string]int{},
		SkippedReasons: map[string]int{},
	}

	// One finding per (endpoint, check) pair: header/behavior issues are
	// the same regardless of how many requests hit the endpoint, and a
	// per-request finding per endpoint drowns the report in duplicates.
	seen := map[string]bool{}
	for _, ex := range exchanges {
		select {
		case <-ctx.Done():
			summary.Note = "cancelled"
			return summary, nil
		default:
		}
		if store.IsCancelled(jobID) {
			summary.Note = "cancelled"
			return summary, nil
		}
		for _, check := range passiveChecks {
			sig := check(ex)
			if sig == nil {
				continue
			}
			key := sig.CheckID + "|" + sig.EndpointID
			if seen[key] {
				continue
			}
			seen[key] = true
			created, err := findings.Save(sig)
			if err != nil {
				continue
			}
			if created {
				summary.NewFindings++
				summary.BySeverity[sig.Severity]++
				summary.ByCheck[sig.CheckID]++
			}
		}
		summary.Scanned++
	}

	summary.DurationMS = time.Since(start).Milliseconds()
	counts, _ := findings.Counts()
	summary.TotalFindings = 0
	for _, n := range counts {
		summary.TotalFindings += n
	}
	if summary.NewFindings == 0 {
		summary.Note = "no new findings — traffic already analyzed or clean"
	}

	if store.IsCancelled(jobID) {
		return summary, nil
	}
	if err := store.MarkDone(jobID, summaryJSON(summary)); err != nil {
		return nil, err
	}
	return summary, nil
}

// summaryJSON marshals a ScanSummary into the map shape jobs expect.
func summaryJSON(s *ScanSummary) map[string]interface{} {
	return map[string]interface{}{
		"mode":            s.Mode,
		"scanned":         s.Scanned,
		"probes_sent":     s.ProbesSent,
		"probes_skipped":  s.ProbesSkipped,
		"skipped_reasons": s.SkippedReasons,
		"new_findings":    s.NewFindings,
		"total_findings":  s.TotalFindings,
		"by_severity":     s.BySeverity,
		"by_check":        s.ByCheck,
		"duration_ms":     s.DurationMS,
		"note":            s.Note,
	}
}

// SeverityRank orders severities for sorted output.
func SeverityRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// SortedByCheck returns check IDs sorted by finding count (desc).
func SortedByCheck(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return m[out[i]] > m[out[j]] })
	return out
}

func errf(format string, a ...interface{}) error {
	return fmt.Errorf(format, a...)
}
