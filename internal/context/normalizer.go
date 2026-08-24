package context

import (
	"regexp"
	"strings"
)

var pathSegmentPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), "{uuid}"},
	{regexp.MustCompile(`^[0-9a-f]{24,}$`), "{hash}"},
	{regexp.MustCompile(`^\d+$`), "{id}"},
	{regexp.MustCompile(`^[A-Za-z0-9_\-\.]{20,}$`), "{param}"},
}

func NormalizePath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		for _, p := range pathSegmentPatterns {
			if p.re.MatchString(seg) {
				segments[i] = p.name
				break
			}
		}
	}
	return strings.Join(segments, "/")
}

func CanonicalPath(template string) string {
	for _, name := range []string{"{id}", "{uuid}", "{hash}", "{param}"} {
		if strings.HasSuffix(template, "/"+name) {
			return strings.TrimSuffix(template, "/"+name)
		}
	}
	return template
}

func isPlaceholder(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

func TemplateFits(template, path string) bool {
	tSegs := strings.Split(template, "/")
	pSegs := strings.Split(path, "/")
	if len(tSegs) != len(pSegs) {
		return false
	}
	for i := range tSegs {
		if isPlaceholder(tSegs[i]) {
			if pSegs[i] == "" {
				return false
			}
			continue
		}
		if tSegs[i] != pSegs[i] {
			return false
		}
	}
	return true
}

func SegmentCount(path string) int {
	parts := strings.Split(path, "/")
	n := 0
	for _, p := range parts {
		if p != "" {
			n++
		}
	}
	return n
}
