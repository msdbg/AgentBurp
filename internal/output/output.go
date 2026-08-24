package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

var JSONMode bool

func Print(v interface{}) {
	if JSONMode {
		PrintJSON(v)
	}
}

func PrintJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "error: json encode: %v\n", err)
	}
}

func PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	sep := make([]string, len(headers))
	for i := range sep {
		sep[i] = strings.Repeat("─", len(headers[i]))
	}
	fmt.Fprintln(w, strings.Join(sep, "\t"))
	for _, row := range rows {
		for len(row) < len(headers) {
			row = append(row, "")
		}
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

func PrintAuto(v interface{}, humanFn func()) {
	if JSONMode {
		PrintJSON(v)
	} else {
		humanFn()
	}
}

func Err(err error) {
	if JSONMode {
		PrintJSON(map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
}

func PrintKV(m map[string]interface{}) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, err := json.Marshal(m[k])
		if err != nil {
			b = []byte(fmt.Sprint(m[k]))
		}
		fmt.Printf("  %-18s %s\n", k+":", string(b))
	}
}

func Success(msg string, data interface{}) {
	if JSONMode {
		PrintJSON(map[string]interface{}{"ok": true, "message": msg, "data": data})
	} else {
		fmt.Printf("✓ %s\n", msg)
	}
}

func DryRun(summary interface{}) {
	type dryRunResult struct {
		DryRun  bool        `json:"dry_run"`
		Summary interface{} `json:"summary"`
	}
	result := dryRunResult{DryRun: true, Summary: summary}
	if JSONMode {
		PrintJSON(result)
	} else {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Printf("DRY RUN — no requests sent\n\n%s\n", data)
	}
}

func TruncateBody(body []byte, maxBytes int) ([]byte, bool) {
	if maxBytes <= 0 || len(body) <= maxBytes {
		return body, false
	}
	return body[:maxBytes], true
}
