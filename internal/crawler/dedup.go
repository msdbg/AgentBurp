// Package crawler implements content discovery: a static crawler that
// follows links, forms, and JS endpoint hints, plus a headless mode that
// renders pages with Chrome via go-rod for JS-heavy apps.
package crawler

import (
	"net/url"
	"sort"
	"strings"
)

// NormalizeURL canonicalizes a URL for dedup: fragment removed, default
// ports stripped, query keys sorted, trailing slash preserved as-is.
func NormalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	if u.Scheme == "http" && u.Port() == "80" {
		u.Host = u.Hostname()
	}
	if u.Scheme == "https" && u.Port() == "443" {
		u.Host = u.Hostname()
	}
	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			for _, v := range q[k] {
				parts = append(parts, k+"="+v)
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

// ResolveLink resolves a possibly-relative href against a base URL.
// Returns empty string when the link cannot be resolved or is not
// http(s).
func ResolveLink(base, href string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	if strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "data:") {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := b.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	if resolved.Host == "" {
		return ""
	}
	return NormalizeURL(resolved.String())
}

// IsStaticResource reports whether a URL points at a non-HTML resource
// that the crawler should skip (images, media, archives, binaries).
func IsStaticResource(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, ext := range []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".avif",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".webm", ".mp3", ".ogg", ".wav", ".avi", ".mov",
		".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".exe", ".msi", ".dmg",
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// SameHost reports whether two URLs share a host.
func SameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return ua.Host == ub.Host
}
