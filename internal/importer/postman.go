package importer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func ParsePostman(source string, data []byte) (*Plan, error) {
	var coll struct {
		Info struct {
			Name string `json:"name"`
		} `json:"info"`
		Item []json.RawMessage `json:"item"`
	}
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil, fmt.Errorf("parse Postman collection: %w", err)
	}
	plan := &Plan{Format: "postman", Source: source}
	if len(coll.Item) == 0 {
		return nil, fmt.Errorf("collection has no items")
	}
	var walk func(items []json.RawMessage)
	walk = func(items []json.RawMessage) {
		for _, raw := range items {
			var node struct {
				Name    string            `json:"name"`
				Request json.RawMessage   `json:"request"`
				Item    []json.RawMessage `json:"item"`
			}
			if err := json.Unmarshal(raw, &node); err != nil {
				continue
			}
			if len(node.Item) > 0 {
				walk(node.Item)
				continue
			}
			if len(node.Request) > 0 {
				req, ok := parsePostmanRequest(node.Request)
				if ok {
					if req.Source == "" {
						req.Source = node.Name
					}
					plan.Requests = append(plan.Requests, req)
				}
			}
		}
	}
	walk(coll.Item)
	if len(plan.Requests) == 0 {
		return nil, fmt.Errorf("no requests found in collection")
	}
	return plan, nil
}

func parsePostmanRequest(raw json.RawMessage) (RequestSpec, bool) {
	var r struct {
		Method string `json:"method"`
		URL    struct {
			Raw string `json:"raw"`
		} `json:"url"`
		Header []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"header"`
		Body struct {
			Mode       string `json:"mode"`
			Raw        string `json:"raw"`
			URLEncoded []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"urlencoded"`
			FormData []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"formdata"`
		} `json:"body"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return RequestSpec{}, false
	}
	req := RequestSpec{Method: strings.ToUpper(r.Method)}
	if r.URL.Raw != "" {
		req.URL = r.URL.Raw
	}
	if req.URL == "" || req.Method == "" {
		return RequestSpec{}, false
	}
	for _, h := range r.Header {
		req.Headers = append(req.Headers, h.Key+": "+h.Value)
	}
	switch r.Body.Mode {
	case "raw":
		if strings.TrimSpace(r.Body.Raw) != "" {
			req.Body = []byte(r.Body.Raw)
			hasCT := false
			for _, h := range req.Headers {
				if strings.HasPrefix(strings.ToLower(h), "content-type:") {
					hasCT = true
				}
			}
			if !hasCT {
				req.Headers = append(req.Headers, "Content-Type: application/json")
			}
		}
	case "urlencoded":
		var parts []string
		for _, kv := range r.Body.URLEncoded {
			parts = append(parts, kv.Key+"="+kv.Value)
		}
		if len(parts) > 0 {
			req.Body = []byte(strings.Join(parts, "&"))
			req.Headers = append(req.Headers, "Content-Type: application/x-www-form-urlencoded")
		}
	case "formdata":
		var parts []string
		for _, kv := range r.Body.FormData {
			parts = append(parts, kv.Key+"="+kv.Value)
		}
		if len(parts) > 0 {
			req.Body = []byte(strings.Join(parts, "&"))
			req.Headers = append(req.Headers, "Content-Type: application/x-www-form-urlencoded")
		}
	}
	return req, true
}

func (p *Plan) SetBaseURL(base string) {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return
	}
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return
	}
	for i := range p.Requests {
		u, err := url.Parse(p.Requests[i].URL)
		if err != nil {
			continue
		}
		if u.Host == "" {
			rel := p.Requests[i].URL
			if !strings.HasPrefix(rel, "/") {
				rel = "/" + rel
			}
			if bu.Path != "" && bu.Path != "/" {
				rel = strings.TrimRight(bu.Path, "/") + rel
			}
			p.Requests[i].URL = bu.Scheme + "://" + bu.Host + rel
			continue
		}
		u.Scheme = bu.Scheme
		u.Host = bu.Host
		if bu.Path != "" && bu.Path != "/" {
			u.Path = strings.TrimRight(bu.Path, "/") + "/" + strings.TrimLeft(u.Path, "/")
			if !strings.HasPrefix(u.Path, "/") {
				u.Path = "/" + u.Path
			}
		}
		p.Requests[i].URL = u.String()
	}
}
