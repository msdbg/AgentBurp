package fuzzer

import (
	"fmt"
	"regexp"
	"strings"
)

type Filters struct {
	StatusCodes []int    `json:"status_codes,omitempty"`
	LengthGT    int      `json:"length_gt,omitempty"`
	LengthLT    int      `json:"length_lt,omitempty"`
	Regex       string   `json:"regex,omitempty"`
	Grep        []string `json:"grep,omitempty"`
}

func (f *Filters) Empty() bool {
	return f == nil || (len(f.StatusCodes) == 0 && f.LengthGT == 0 && f.LengthLT == 0 && f.Regex == "" && len(f.Grep) == 0)
}

var filterReCache = map[string]*regexp.Regexp{}

func (f *Filters) compileRegex() (*regexp.Regexp, error) {
	if f.Regex == "" {
		return nil, nil
	}
	if re, ok := filterReCache[f.Regex]; ok {
		return re, nil
	}
	re, err := regexp.Compile(f.Regex)
	if err != nil {
		return nil, fmt.Errorf("invalid filter regex %q: %w", f.Regex, err)
	}
	filterReCache[f.Regex] = re
	return re, nil
}

func (f *Filters) Match(status int, length int, body []byte) (bool, string) {
	if f.Empty() {
		return false, ""
	}
	var reasons []string

	if len(f.StatusCodes) > 0 {
		ok := false
		for _, s := range f.StatusCodes {
			if status == s {
				ok = true
				break
			}
		}
		if !ok {
			return false, ""
		}
		reasons = append(reasons, fmt.Sprintf("status=%d", status))
	}
	if f.LengthGT > 0 && length <= f.LengthGT {
		return false, ""
	}
	if f.LengthGT > 0 {
		reasons = append(reasons, fmt.Sprintf("length>%d (%d)", f.LengthGT, length))
	}
	if f.LengthLT > 0 && length >= f.LengthLT {
		return false, ""
	}
	if f.LengthLT > 0 {
		reasons = append(reasons, fmt.Sprintf("length<%d (%d)", f.LengthLT, length))
	}
	if f.Regex != "" {
		re, err := f.compileRegex()
		if err != nil || !re.Match(body) {
			return false, ""
		}
		reasons = append(reasons, fmt.Sprintf("regex=%q", f.Regex))
	}
	if len(f.Grep) > 0 {
		text := string(body)
		for _, g := range f.Grep {
			if !strings.Contains(text, g) {
				return false, ""
			}
		}
		reasons = append(reasons, fmt.Sprintf("grep=%q", strings.Join(f.Grep, ",")))
	}
	return true, strings.Join(reasons, " ")
}
