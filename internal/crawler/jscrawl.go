package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	jsAbsRe      = regexp.MustCompile(`["'` + "`" + `](https?://[^"'\s` + "`" + `)]+)["'` + "`" + `]`)
	jsRelRe      = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_\-./{}$:]+(?:/[a-zA-Z0-9_\-./{}$:]*)?)["'` + "`" + `]`)
	jsAPIRe      = regexp.MustCompile(`["'` + "`" + `]((?:api|v\d+|admin|graphql|rest)[a-zA-Z0-9_\-/.]*)["'` + "`" + `]`)
	fetchRe      = regexp.MustCompile(`(?i)fetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]{2,})["'` + "`" + `]`)
	openRe       = regexp.MustCompile(`(?i)(?:open)\s*\(\s*["'` + "`" + `][^"'` + "`" + `]*["'` + "`" + `]\s*,\s*["'` + "`" + `]([^"'` + "`" + `]{2,})["'` + "`" + `]`)
	methodCallRe = regexp.MustCompile(`(?i)(?:get|post|put|delete|patch|request|sendbeacon|send)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]{2,})["'` + "`" + `]`)
)

var jsSkip = []string{
	".css", ".js", ".map", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf",
	"//cdn.", "//fonts.", "//platform.", "//ajax.", "//www.googletagmanager.com",
	"https://www.w3.org", "http://www.w3.org", "schema.org", "xmlns", "api.whatsapp",
}

func ExtractJSPaths(js string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len(s) < 3 || seen[s] {
			return
		}
		if strings.Contains(s, "${") {
			return
		}
		if !strings.Contains(s, "/") {
			return
		}
		if p := pathOf(s); strings.HasPrefix(p, "/static/js/") || strings.HasPrefix(p, "/static/css/") || strings.HasPrefix(p, "/static/media/") {
			lower := strings.ToLower(p)
			if !hasAssetExt(lower) {
				return
			}
		}
		for _, skip := range jsSkip {
			if strings.Contains(s, skip) {
				return
			}
		}
		seen[s] = true
		out = append(out, s)
	}

	for _, re := range []*regexp.Regexp{jsAbsRe, fetchRe, openRe, methodCallRe} {
		for _, m := range re.FindAllStringSubmatch(js, -1) {
			add(m[1])
		}
	}
	for _, m := range jsRelRe.FindAllStringSubmatch(js, -1) {
		p := m[1]
		if looksLikeEndpoint(p) {
			add(p)
		}
	}
	for _, m := range jsAPIRe.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	return out
}

func pathOf(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if i := strings.Index(s, "//"); i != -1 {
			rest := s[i+2:]
			if j := strings.IndexByte(rest, '/'); j != -1 {
				return rest[j:]
			}
			return "/"
		}
	}
	return s
}

func hasAssetExt(p string) bool {
	for _, ext := range []string{".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".woff", ".woff2", ".ttf", ".ico"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func looksLikeEndpoint(p string) bool {
	if len(p) < 3 || p == "/" {
		return false
	}
	lower := strings.ToLower(p)
	if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") ||
		strings.HasSuffix(lower, ".ico") || strings.HasSuffix(lower, ".css") {
		return false
	}
	if strings.Count(p, "/") == 1 {
		seg := strings.TrimPrefix(lower, "/")
		seg = strings.Split(seg, "?")[0]
		seg = strings.Split(seg, "#")[0]
		if isHTMLTag(seg) {
			return false
		}
	}
	return strings.Count(p, "/") >= 1
}

func isHTMLTag(s string) bool {
	switch s {
	case "a", "abbr", "address", "area", "article", "aside", "audio", "b", "base", "bdi", "bdo", "blockquote", "body", "br", "button", "canvas", "caption", "cite", "code", "col", "colgroup", "data", "datalist", "dd", "del", "details", "dfn", "dialog", "div", "dl", "dt", "em", "embed", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main", "map", "mark", "menu", "meta", "meter", "nav", "noscript", "object", "ol", "optgroup", "option", "output", "p", "picture", "pre", "progress", "q", "rp", "rt", "ruby", "s", "samp", "script", "section", "select", "small", "source", "span", "strong", "style", "sub", "summary", "sup", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track", "u", "ul", "var", "video", "wbr":
		return true
	}
	return false
}

func JSEndpointURLs(baseURL string, js string) []string {
	seen := map[string]bool{}
	var out []string
	origin := originOf(baseURL)
	for _, raw := range ExtractJSPaths(js) {
		var u string
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") ||
			strings.HasPrefix(raw, "//") {
			u = ResolveLink(baseURL, raw)
		} else {
			u = ResolveLink(origin, raw)
		}
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
