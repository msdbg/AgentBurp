package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Timeout         time.Duration
	FollowRedirects bool
	MaxRedirects    int
	RatePerSec      int
}

type Client struct {
	http  *http.Client
	opts  Options
	mu    sync.Mutex
	slots map[string]*rateSlot
}

type rateSlot struct {
	interval time.Duration
	next     time.Time
}

type redirectCookiesKey struct{}

func New(opts Options) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Jar:     jar,
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Response != nil {
				if collector, ok := req.Context().Value(redirectCookiesKey{}).(*[]string); ok {
					*collector = append(*collector, req.Response.Header.Values("Set-Cookie")...)
				}
			}
			if len(via) >= opts.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", opts.MaxRedirects)
			}
			if !opts.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &Client{http: c, opts: opts, slots: map[string]*rateSlot{}}
}

func (c *Client) waitSlot(ctx context.Context, host string) error {
	if c.opts.RatePerSec <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(c.opts.RatePerSec)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	c.mu.Lock()
	slot, ok := c.slots[host]
	if !ok {
		slot = &rateSlot{interval: interval, next: time.Now()}
		c.slots[host] = slot
	}
	wait := time.Until(slot.next)
	slot.next = slot.next.Add(interval)
	c.mu.Unlock()

	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	return nil
}
func (c *Client) Do(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	if err := c.waitSlot(ctx, hostOf(rawURL)); err != nil {
		return nil, nil, err
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(string(body))
	}
	collected := &[]string{}
	ctx = context.WithValue(ctx, redirectCookiesKey{}, collected)
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	const maxResponseBody = 50 * 1024 * 1024
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}
	if len(*collected) > 0 {
		merged := make([]string, 0, len(*collected)+len(resp.Header["Set-Cookie"]))
		merged = append(merged, *collected...)
		merged = append(merged, resp.Header["Set-Cookie"]...)
		resp.Header["Set-Cookie"] = merged
	}
	return resp, respBody, nil
}

func (c *Client) DoSimple(ctx context.Context, method, rawURL string) (*http.Response, []byte, error) {
	return c.Do(ctx, method, rawURL, nil, nil)
}

func hostOf(rawURL string) string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i != -1 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i != -1 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i != -1 {
		rest = rest[i+1:]
	}
	if i := strings.IndexByte(rest, ':'); i != -1 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}
