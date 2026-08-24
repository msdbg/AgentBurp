package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

func (r *Runner) render(ctx context.Context, rawURL string) ([]byte, []string, error) {
	lc := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("--disable-gpu")

	if r.opts.ProxyURL != "" {
		lc = lc.Proxy(r.opts.ProxyURL)
	}
	if r.opts.SessionID != "" {
		lc = lc.Set("--disable-web-security")
	}

	controlURL, err := lc.Launch()
	if err != nil {
		return nil, nil, fmt.Errorf("launch headless Chrome: %w (install Chrome or use static crawl)", err)
	}
	browser := rod.New().ControlURL(controlURL).Context(ctx).MustConnect()
	defer browser.Close()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, nil, err
	}
	defer page.Close()

	if r.opts.SessionID != "" {
		if cookies := r.sessionCookies(rawURL); len(cookies) > 0 {
			if err := page.SetCookies(cookies); err != nil {
				return nil, nil, fmt.Errorf("inject session cookies: %w", err)
			}
		}
	}

	if err := page.Navigate(rawURL); err != nil {
		return nil, nil, err
	}

	page.Timeout(20 * time.Second)
	page.WaitLoad()

	lastCount := -1
	stable := 0
	for i := 0; i < 12; i++ {
		time.Sleep(500 * time.Millisecond)
		v, err := page.Eval(`() => performance.getEntriesByType('resource').length`)
		if err != nil {
			continue
		}
		var count int
		if raw, ok := v.Value.Raw().([]byte); ok {
			json.Unmarshal(raw, &count)
		}
		if count == lastCount {
			stable++
			if stable >= 2 {
				break
			}
		} else {
			stable = 0
			lastCount = count
		}
	}

	dom, err := page.HTML()
	if err != nil {
		return nil, nil, err
	}

	var netURLs []string
	if v, err := page.Eval(`() => performance.getEntriesByType('resource').map(e => e.name)`); err == nil {
		var names []string
		if raw, ok := v.Value.Raw().([]byte); ok && json.Unmarshal(raw, &names) == nil {
			for _, n := range names {
				if strings.HasPrefix(n, "http://") || strings.HasPrefix(n, "https://") {
					netURLs = append(netURLs, NormalizeURL(n))
				}
			}
		}
	}
	return []byte(dom), netURLs, nil
}

func (r *Runner) sessionCookies(rawURL string) []*proto.NetworkCookieParam {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}
	var params []*proto.NetworkCookieParam
	for _, h := range r.session {
		if !strings.EqualFold(h.Name, "Cookie") {
			continue
		}
		for _, part := range strings.Split(h.Value, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 || kv[0] == "" {
				continue
			}
			params = append(params, &proto.NetworkCookieParam{
				Name:   kv[0],
				Value:  kv[1],
				Domain: host,
				Path:   "/",
			})
		}
	}
	return params
}
