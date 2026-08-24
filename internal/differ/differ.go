package differ

import (
	"sort"
	"strings"

	"github.com/msdbg/AgentBurp/internal/models"
)

type FieldChange struct {
	Changed bool   `json:"changed"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

type HeaderChange struct {
	Name   string `json:"name"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type DiffLine struct {
	Type string `json:"type"`
	Line string `json:"line"`
}

type BodyDiff struct {
	Changed    bool       `json:"changed"`
	BeforeHash string     `json:"before_hash,omitempty"`
	AfterHash  string     `json:"after_hash,omitempty"`
	BeforeSize int        `json:"before_size"`
	AfterSize  int        `json:"after_size"`
	Lines      []DiffLine `json:"lines,omitempty"`
}

type DiffResult struct {
	Kind          string         `json:"kind"`
	Same          bool           `json:"same"`
	Status        *FieldChange   `json:"status,omitempty"`
	Method        *FieldChange   `json:"method,omitempty"`
	URL           *FieldChange   `json:"url,omitempty"`
	Reason        *FieldChange   `json:"reason,omitempty"`
	Headers       HeaderDiff     `json:"headers,omitempty"`
	Body          *BodyDiff      `json:"body,omitempty"`
	HeaderChanges []HeaderChange `json:"header_changes"`
}

type HeaderDiff struct {
	Changed  bool           `json:"changed"`
	Added    []HeaderChange `json:"added"`
	Removed  []HeaderChange `json:"removed"`
	Modified []HeaderChange `json:"modified"`
}

func DiffRequests(a, b *models.Request) *DiffResult {
	res := &DiffResult{Kind: "request"}

	method := &FieldChange{Before: a.Method, After: b.Method, Changed: a.Method != b.Method}
	u := &FieldChange{Before: a.URL, After: b.URL, Changed: a.URL != b.URL}

	hd := diffHeaders(a.Headers, b.Headers)

	bd := diffBodies(a.Body, b.Body, a.BodyHash, b.BodyHash, a.BodySize, b.BodySize)
	if len(a.Body) == 0 && len(b.Body) == 0 && (a.BodySize != b.BodySize) {
		bd = &BodyDiff{Changed: true, BeforeHash: a.BodyHash, AfterHash: b.BodyHash,
			BeforeSize: a.BodySize, AfterSize: b.BodySize}
	}

	res.Method = method
	res.URL = u
	res.Headers = hd
	res.Body = bd
	res.Same = !method.Changed && !u.Changed && !hd.Changed && !bd.Changed
	return res
}

func DiffResponses(a, b *models.Response) *DiffResult {
	res := &DiffResult{Kind: "response"}

	status := &FieldChange{
		Before:  itoa(a.StatusCode),
		After:   itoa(b.StatusCode),
		Changed: a.StatusCode != b.StatusCode,
	}
	reason := &FieldChange{Before: a.Reason, After: b.Reason, Changed: a.Reason != b.Reason}

	hd := diffHeaders(a.Headers, b.Headers)
	bd := diffBodies(a.Body, b.Body, a.BodyHash, b.BodyHash, a.BodySize, b.BodySize)
	if len(a.Body) == 0 && len(b.Body) == 0 && (a.BodySize != b.BodySize) {
		bd = &BodyDiff{Changed: true, BeforeHash: a.BodyHash, AfterHash: b.BodyHash,
			BeforeSize: a.BodySize, AfterSize: b.BodySize}
	}

	res.Status = status
	res.Reason = reason
	res.Headers = hd
	res.Body = bd
	res.Same = !status.Changed && !reason.Changed && !hd.Changed && !bd.Changed
	return res
}

func diffHeaders(a, b []models.Header) HeaderDiff {
	am := headerMap(a)
	bm := headerMap(b)

	var out HeaderDiff
	names := sortedUnion(am, bm)
	for _, n := range names {
		av, aok := am[n]
		bv, bok := bm[n]
		switch {
		case aok && !bok:
			out.Changed = true
			out.Removed = append(out.Removed, HeaderChange{Name: av.original, Before: av.value})
		case !aok && bok:
			out.Changed = true
			out.Added = append(out.Added, HeaderChange{Name: bv.original, After: bv.value})
		case av.value != bv.value:
			out.Changed = true
			out.Modified = append(out.Modified, HeaderChange{Name: bv.original, Before: av.value, After: bv.value})
		}
	}
	return out
}

type headerVal struct {
	value    string
	original string
}

func headerMap(hs []models.Header) map[string]headerVal {
	m := make(map[string]headerVal, len(hs))
	for _, h := range hs {
		key := strings.ToLower(h.Name)
		if _, exists := m[key]; !exists {
			m[key] = headerVal{value: h.Value, original: h.Name}
		}
	}
	return m
}

func sortedUnion(a, b map[string]headerVal) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func diffBodies(aBody, bBody []byte, aHash, bHash string, aSize, bSize int) *BodyDiff {
	bd := &BodyDiff{
		BeforeHash: aHash, AfterHash: bHash,
		BeforeSize: aSize, AfterSize: bSize,
	}
	if len(aBody) == 0 && len(bBody) == 0 {
		bd.Changed = bd.BeforeHash != bd.AfterHash
		return bd
	}
	if len(aBody) == 0 || len(bBody) == 0 {
		bd.Changed = true
		return bd
	}
	if len(aBody) == len(bBody) && string(aBody) == string(bBody) {
		return bd
	}
	bd.Changed = true
	bd.Lines = lineDiff(string(aBody), string(bBody), 100)
	return bd
}

func lineDiff(before, after string, maxLines int) []DiffLine {
	aLines := splitLines(before)
	bLines := splitLines(after)

	type cell struct {
		length int
		dir    byte
	}
	table := make([][]cell, len(aLines)+1)
	for i := range table {
		table[i] = make([]cell, len(bLines)+1)
	}
	for i := 1; i <= len(aLines); i++ {
		for j := 1; j <= len(bLines); j++ {
			if aLines[i-1] == bLines[j-1] {
				table[i][j] = cell{length: table[i-1][j-1].length + 1, dir: 'd'}
			} else if table[i-1][j].length >= table[i][j-1].length {
				table[i][j] = cell{length: table[i-1][j].length, dir: 'u'}
			} else {
				table[i][j] = cell{length: table[i][j-1].length, dir: 'l'}
			}
		}
	}

	var out []DiffLine
	i, j := len(aLines), len(bLines)
	var stack []DiffLine
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && table[i][j].dir == 'd' {
			stack = append(stack, DiffLine{Type: "ctx", Line: aLines[i-1]})
			i--
			j--
		} else if i > 0 && (j == 0 || table[i][j].dir == 'u') {
			stack = append(stack, DiffLine{Type: "del", Line: aLines[i-1]})
			i--
		} else {
			stack = append(stack, DiffLine{Type: "add", Line: bLines[j-1]})
			j--
		}
	}
	for k := len(stack) - 1; k >= 0; k-- {
		out = append(out, stack[k])
		if len(out) >= maxLines {
			out = append(out, DiffLine{Type: "ctx", Line: "… (diff truncated)"})
			break
		}
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
