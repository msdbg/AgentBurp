package fuzzer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type Position struct {
	Location string
	Kind     string
	Name     string
}

func ParsePosition(location string) (*Position, error) {
	dot := strings.IndexByte(location, '.')
	if dot <= 0 || dot == len(location)-1 {
		return nil, fmt.Errorf("invalid position %q — use kind.name (e.g. query.id, body.username, header.X-User-Id, cookie.csrf, path.userId)", location)
	}
	kind, name := location[:dot], location[dot+1:]
	switch kind {
	case "query", "body", "header", "cookie", "path":
	default:
		return nil, fmt.Errorf("invalid position kind %q — use query|body|header|cookie|path", kind)
	}
	if name == "" {
		return nil, fmt.Errorf("position %q: empty parameter name", location)
	}
	return &Position{Location: location, Kind: kind, Name: name}, nil
}

type Request struct {
	Method  string
	URL     string
	Headers []string
	Body    []byte
}

func Apply(base *Request, positions []*Position, payloads map[string]string) (*Request, error) {
	out := &Request{
		Method:  base.Method,
		URL:     base.URL,
		Headers: append([]string{}, base.Headers...),
		Body:    append([]byte{}, base.Body...),
	}
	queryVals := map[string][]string{}
	headerVals := map[string]string{}
	cookieVals := map[string]string{}
	bodyChanged := false
	pathChanged := false
	hadQuery := false

	for _, p := range positions {
		val, ok := payloads[p.Location]
		if !ok {
			continue
		}
		switch p.Kind {
		case "query":
			hadQuery = true
			queryVals[p.Name] = []string{val}
		case "header":
			headerVals[p.Name] = val
		case "cookie":
			cookieVals[p.Name] = val
		case "body":
			bodyChanged = true
			if err := applyBodyPosition(out, p.Name, val); err != nil {
				return nil, err
			}
		case "path":
			pathChanged = true
			out.URL = replacePathSegment(out.URL, p.Name, val)
		}
	}

	if hadQuery {
		u, err := url.Parse(out.URL)
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		q := u.Query()
		for k, vs := range queryVals {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
		out.URL = u.String()
	}
	if pathChanged {
		_ = pathChanged
	}
	if len(headerVals) > 0 {
		var headers []string
		for _, h := range out.Headers {
			name, _, _ := strings.Cut(h, ":")
			if v, ok := headerVals[strings.TrimSpace(name)]; ok {
				headers = append(headers, strings.TrimSpace(name)+": "+v)
				delete(headerVals, strings.TrimSpace(name))
			} else {
				headers = append(headers, h)
			}
		}
		for name, v := range headerVals {
			headers = append(headers, name+": "+v)
		}
		out.Headers = headers
	}
	if len(cookieVals) > 0 {
		out.Headers = applyCookiePositions(out.Headers, cookieVals)
	}
	_ = bodyChanged
	return out, nil
}

func replacePathSegment(rawURL, segment, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parts := strings.Split(u.Path, "/")
	for i, seg := range parts {
		if seg == segment {
			parts[i] = value
		}
	}
	u.Path = strings.Join(parts, "/")
	return u.String()
}

func applyCookiePositions(headers []string, vals map[string]string) []string {
	var out []string
	for _, h := range headers {
		name, v, ok := strings.Cut(h, ":")
		if !ok {
			out = append(out, h)
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(name), "Cookie") {
			out = append(out, h)
			continue
		}
		cookies := map[string]string{}
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			k, val, _ := strings.Cut(part, "=")
			cookies[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
		for k, val := range vals {
			cookies[k] = val
		}
		var parts []string
		for k, val := range cookies {
			parts = append(parts, k+"="+val)
		}
		out = append(out, "Cookie: "+strings.Join(parts, "; "))
	}
	return out
}

func applyBodyPosition(req *Request, name, value string) error {
	body := req.Body
	trimmed := strings.TrimSpace(string(body))
	ct := contentTypeOf(req.Headers)

	switch {
	case strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "["):
		var obj map[string]interface{}
		if err := json.Unmarshal(body, &obj); err != nil {
			return fmt.Errorf("position body.%s: body is not valid JSON: %w", name, err)
		}
		setJSONPath(obj, name, value)
		enc, err := json.Marshal(obj)
		if err != nil {
			return err
		}
		req.Body = enc
	case strings.Contains(ct, "multipart/form-data"):
		return applyMultipartPosition(req, name, value)
	default:
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return fmt.Errorf("position body.%s: body is not form-encoded: %w", name, err)
		}
		vals.Set(name, value)
		req.Body = []byte(vals.Encode())
	}
	return nil
}

func contentTypeOf(headers []string) string {
	for _, h := range headers {
		name, v, ok := strings.Cut(h, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func setJSONPath(obj map[string]interface{}, path, value string) {
	parts := strings.Split(path, ".")
	cur := obj
	for i := 0; i < len(parts)-1; i++ {
		next, ok := cur[parts[i]].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			cur[parts[i]] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

func applyMultipartPosition(req *Request, name, value string) error {
	body := string(req.Body)
	boundary := multipartBoundary(contentTypeOf(req.Headers))
	if boundary == "" {
		return fmt.Errorf("position body.%s: multipart body without boundary", name)
	}
	delim := "--" + boundary
	parts := strings.Split(body, delim)
	var rebuilt []string
	replaced := false
	for i, part := range parts {
		if i == 0 || i == len(parts)-1 {
			continue
		}
		if strings.Contains(part, `name="`+name+`"`) {
			idx := strings.Index(part, "\r\n\r\n")
			if idx == -1 {
				idx = strings.Index(part, "\n\n")
			}
			if idx != -1 {
				part = part[:idx+4] + value
				if !strings.HasPrefix(part, "\r\n") && !strings.HasPrefix(part, "\n") {
					part = "\r\n" + part
				}
			}
			replaced = true
		}
		rebuilt = append(rebuilt, delim+part)
	}
	if !replaced {
		return fmt.Errorf("position body.%s: no multipart part named %q", name, name)
	}
	rebuilt = append(rebuilt, delim+"--")
	req.Body = []byte(strings.Join(rebuilt, ""))
	return nil
}

func multipartBoundary(ct string) string {
	for _, part := range strings.Split(ct, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "boundary=") {
			return strings.Trim(strings.TrimPrefix(part, "boundary="), `"`)
		}
	}
	return ""
}
