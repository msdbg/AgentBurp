package sequencer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type TokenReport struct {
	SampleSize      int            `json:"sample_size"`
	UniqueTokens    int            `json:"unique_tokens"`
	DuplicateTokens int            `json:"duplicate_tokens"`
	AvgLength       float64        `json:"avg_length"`
	EntropyPerChar  float64        `json:"entropy_bits_per_char"`
	EntropyTotal    float64        `json:"entropy_total_bits"`
	Charset         string         `json:"charset"` // hex|base64|alphanumeric|numeric|uuid|mixed
	CharClasses     map[string]int `json:"char_class_distribution"`
	Sequential      bool           `json:"sequential"`
	Monotonic       bool           `json:"monotonic"`
	PredictedNext   string         `json:"predicted_next,omitempty"`
	Rating          string         `json:"rating"`
	Notes           []string       `json:"notes"`
}

var (
	hexRx   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	b64Rx   = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	numRx   = regexp.MustCompile(`^[0-9]+$`)
	alnumRx = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	uuidRx  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func Analyze(tokens []string) *TokenReport {
	report := &TokenReport{SampleSize: len(tokens), CharClasses: map[string]int{}}
	if len(tokens) == 0 {
		report.Rating = "n/a"
		report.Notes = append(report.Notes, "empty sample — capture more tokens")
		return report
	}

	clean := make([]string, 0, len(tokens))
	seen := map[string]bool{}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		t = strings.Trim(t, `"'`)
		if t == "" {
			continue
		}
		clean = append(clean, t)
		if !seen[t] {
			seen[t] = true
		}
	}
	if len(clean) == 0 {
		report.Rating = "n/a"
		return report
	}
	report.UniqueTokens = len(seen)
	report.DuplicateTokens = len(clean) - len(seen)
	if report.DuplicateTokens > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d of %d tokens were duplicates — tokens may be re-used", report.DuplicateTokens, len(clean)))
	}

	lengthSum := 0
	charCount := 0
	freq := map[byte]int{}
	for _, t := range clean {
		lengthSum += len(t)
		charCount += len(t)
		for i := 0; i < len(t); i++ {
			freq[t[i]]++
			switch {
			case t[i] >= 'a' && t[i] <= 'z':
				report.CharClasses["lower"]++
			case t[i] >= 'A' && t[i] <= 'Z':
				report.CharClasses["upper"]++
			case t[i] >= '0' && t[i] <= '9':
				report.CharClasses["digit"]++
			default:
				report.CharClasses["symbol"]++
			}
		}
	}
	report.AvgLength = math.Round(float64(lengthSum)/float64(len(clean))*100) / 100

	entropy := 0.0
	for _, n := range freq {
		p := float64(n) / float64(charCount)
		entropy -= p * math.Log2(p)
	}
	report.EntropyPerChar = math.Round(entropy*1000) / 1000
	report.EntropyTotal = math.Round(report.EntropyPerChar*report.AvgLength*10) / 10

	classes := map[string]int{}
	for _, t := range clean {
		switch {
		case uuidRx.MatchString(t):
			classes["uuid"]++
		case numRx.MatchString(t):
			classes["numeric"]++
		case len(t)%2 == 0 && hexRx.MatchString(t):
			classes["hex"]++
		case b64Rx.MatchString(t) && len(t) >= 16:
			classes["base64"]++
		case alnumRx.MatchString(t):
			classes["alphanumeric"]++
		default:
			classes["mixed"]++
		}
	}
	best, bestN := "mixed", 0
	for c, n := range classes {
		if n > bestN {
			best, bestN = c, n
		}
	}
	report.Charset = best
	if report.Charset == "uuid" {
		report.Notes = append(report.Notes, "tokens look like UUIDs — random unless a sequential variant (v1) is used")
	}

	report.Sequential, report.Monotonic, report.PredictedNext = detectSequence(clean)

	report.Rating = rate(report)
	return report
}

func detectSequence(tokens []string) (sequential, monotonic bool, next string) {
	nums := make([]int64, 0, len(tokens))
	for _, t := range tokens {
		if !numRx.MatchString(t) {
			return false, false, ""
		}
		var n int64
		if _, err := fmt.Sscanf(t, "%d", &n); err != nil {
			return false, false, ""
		}
		nums = append(nums, n)
	}
	sorted := append([]int64(nil), nums...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	monotonic = true
	step := int64(0)
	stepSet := false
	for i := 1; i < len(sorted); i++ {
		d := sorted[i] - sorted[i-1]
		if d <= 0 {
			monotonic = false
			break
		}
		if !stepSet {
			step = d
			stepSet = true
		} else if d != step {
			stepSet = false
		}
	}
	if monotonic && stepSet && step > 0 {
		sequential = true
		next = fmt.Sprintf("%d", sorted[len(sorted)-1]+step)
	}
	return sequential, monotonic, next
}

var maxBitsPerChar = map[string]float64{
	"hex":          4.0,
	"base64":       6.0,
	"numeric":      math.Log2(10),
	"alphanumeric": math.Log2(62),
	"uuid":         4.0,
}

func rate(r *TokenReport) string {
	if r.Sequential || r.AvgLength < 6 {
		return "very-weak"
	}
	maxBits := 6.0
	if m, ok := maxBitsPerChar[r.Charset]; ok {
		maxBits = m
	}
	ratio := r.EntropyPerChar / maxBits
	switch {
	case ratio >= 0.85 && r.AvgLength >= 12:
		return "strong"
	case ratio >= 0.7 && r.AvgLength >= 10:
		return "good"
	case ratio >= 0.45:
		return "weak"
	default:
		return "very-weak"
	}
}

func CaptureTokens(conn *sql.DB, projectID, from, field string) ([]string, error) {
	rows, err := conn.Query(`
		SELECT resp.headers_json, resp.body_blob FROM responses resp
		JOIN requests r ON r.id = resp.request_id
		WHERE r.project_id = ? ORDER BY resp.created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var headersJSON string
		var body []byte
		if err := rows.Scan(&headersJSON, &body); err != nil {
			return nil, err
		}
		h := http.Header{}
		var pairs []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal([]byte(headersJSON), &pairs); err == nil {
			for _, p := range pairs {
				h.Add(p.Name, p.Value)
			}
		}

		switch from {
		case "header":
			if v := h.Get(field); v != "" {
				tokens = append(tokens, v)
			}
		case "cookie":
			for _, raw := range h.Values("Set-Cookie") {
				parts := strings.SplitN(raw, "=", 2)
				if len(parts) != 2 {
					continue
				}
				if !strings.EqualFold(strings.TrimSpace(parts[0]), field) {
					continue
				}
				value := parts[1]
				if i := strings.IndexByte(value, ';'); i != -1 {
					value = value[:i]
				}
				tokens = append(tokens, strings.TrimSpace(value))
			}
		case "body":
			var obj map[string]interface{}
			if json.Unmarshal(body, &obj) == nil {
				if v, ok := obj[field].(string); ok {
					tokens = append(tokens, v)
				}
			}
		}
	}
	return tokens, rows.Err()
}
