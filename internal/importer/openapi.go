package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

type RequestSpec struct {
	Method  string
	URL     string
	Headers []string
	Body    []byte
	Source  string
}

type Plan struct {
	Format   string
	Source   string
	BaseURL  string
	Requests []RequestSpec
	Warnings []string
}

func LoadFileOrURL(ref string) ([]byte, error) {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		client := &http.Client{Timeout: 30e9}
		resp, err := client.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", ref, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch %s: HTTP %d", ref, resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(ref)
}

func ParseOpenAPI(source string, data []byte) (*Plan, error) {
	var root map[string]interface{}
	if strings.TrimSpace(string(data))[0] == '{' {
		if err := json.Unmarshal(data, &root); err != nil {
			return nil, fmt.Errorf("parse OpenAPI JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, fmt.Errorf("parse OpenAPI YAML: %w", err)
		}
	}

	plan := &Plan{Format: "openapi", Source: source}
	if v, ok := root["swagger"].(string); ok && strings.HasPrefix(v, "2.") {
		return parseSwagger2(root, plan)
	}
	if v, ok := root["openapi"].(string); ok && strings.HasPrefix(v, "3.") {
		return parseOpenAPI3(root, plan)
	}
	return nil, fmt.Errorf("unsupported spec: expected swagger: 2.x or openapi: 3.x")
}

func parseOpenAPI3(root map[string]interface{}, plan *Plan) (*Plan, error) {
	if servers, ok := root["servers"].([]interface{}); ok && len(servers) > 0 {
		if s, ok := servers[0].(map[string]interface{}); ok {
			if u, ok := s["url"].(string); ok {
				plan.BaseURL = strings.TrimRight(u, "/")
			}
		}
	}
	paths, _ := root["paths"].(map[string]interface{})
	for p, item := range paths {
		pm, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		pathParams := paramList(pm["parameters"])
		for method, op := range pm {
			m := strings.ToUpper(method)
			if m != "GET" && m != "POST" && m != "PUT" && m != "DELETE" && m != "PATCH" &&
				m != "HEAD" && m != "OPTIONS" {
				continue
			}
			opm, ok := op.(map[string]interface{})
			if !ok {
				continue
			}
			opParams := append(paramList(opm["parameters"]), pathParams...)

			var queryParts []string
			for _, prm := range opParams {
				if prm["in"] != "query" {
					continue
				}
				name, _ := prm["name"].(string)
				if name == "" {
					continue
				}
				val := exampleValue(prm)
				if val == "" {
					val = "FUZZ"
				}
				queryParts = append(queryParts, url.QueryEscape(name)+"="+url.QueryEscape(val))
			}

			fullPath := p
			for _, prm := range opParams {
				if prm["in"] != "path" {
					continue
				}
				name, _ := prm["name"].(string)
				if name == "" {
					continue
				}
				val := exampleValue(prm)
				if val == "" {
					val = "1"
				}
				fullPath = strings.ReplaceAll(fullPath, "{"+name+"}", val)
			}

			req := RequestSpec{
				Method: m,
				URL:    plan.BaseURL + fullPath,
				Source: opSummary(opm, method),
			}
			if len(queryParts) > 0 {
				sep := "?"
				if strings.Contains(req.URL, "?") {
					sep = "&"
				}
				req.URL += sep + strings.Join(queryParts, "&")
			}

			for _, prm := range opParams {
				if prm["in"] != "header" {
					continue
				}
				name, _ := prm["name"].(string)
				if name == "" {
					continue
				}
				val := exampleValue(prm)
				if val == "" {
					val = "FUZZ"
				}
				req.Headers = append(req.Headers, name+": "+val)
			}

			if rb, ok := opm["requestBody"].(map[string]interface{}); ok {
				body, ct := buildRequestBody(rb)
				if body != nil {
					req.Body = body
					req.Headers = append(req.Headers, "Content-Type: "+ct)
				}
			}
			plan.Requests = append(plan.Requests, req)
		}
	}
	if plan.BaseURL == "" {
		plan.Warnings = append(plan.Warnings, "no servers[].url found — use --base-url to set the target")
	}
	if len(plan.Requests) == 0 {
		return nil, fmt.Errorf("no operations found in spec")
	}
	return plan, nil
}

func parseSwagger2(root map[string]interface{}, plan *Plan) (*Plan, error) {
	if v, ok := root["host"].(string); ok && v != "" {
		scheme := "http"
		if ss, ok := root["schemes"].([]interface{}); ok && len(ss) > 0 {
			scheme, _ = ss[0].(string)
		}
		basePath, _ := root["basePath"].(string)
		plan.BaseURL = scheme + "://" + v + strings.TrimRight(basePath, "/")
	}
	paths, _ := root["paths"].(map[string]interface{})
	for p, item := range paths {
		pm, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		pathParams := paramList(pm["parameters"])
		for method, op := range pm {
			m := strings.ToUpper(method)
			if m != "GET" && m != "POST" && m != "PUT" && m != "DELETE" && m != "PATCH" &&
				m != "HEAD" && m != "OPTIONS" {
				continue
			}
			opm, ok := op.(map[string]interface{})
			if !ok {
				continue
			}
			opParams := append(paramList(opm["parameters"]), pathParams...)

			var queryParts []string
			fullPath := p
			for _, prm := range opParams {
				in, _ := prm["in"].(string)
				name, _ := prm["name"].(string)
				if name == "" {
					continue
				}
				switch in {
				case "query":
					val := exampleValue(prm)
					if val == "" {
						val = "FUZZ"
					}
					queryParts = append(queryParts, url.QueryEscape(name)+"="+url.QueryEscape(val))
				case "path":
					val := exampleValue(prm)
					if val == "" {
						val = "1"
					}
					fullPath = strings.ReplaceAll(fullPath, "{"+name+"}", val)
				}
			}

			req := RequestSpec{Method: m, URL: plan.BaseURL + fullPath, Source: opSummary(opm, method)}
			for _, prm := range opParams {
				if prm["in"] != "header" {
					continue
				}
				name, _ := prm["name"].(string)
				val := exampleValue(prm)
				if val == "" {
					val = "FUZZ"
				}
				req.Headers = append(req.Headers, name+": "+val)
			}
			if len(queryParts) > 0 {
				sep := "?"
				if strings.Contains(req.URL, "?") {
					sep = "&"
				}
				req.URL += sep + strings.Join(queryParts, "&")
			}
			if bp, ok := opm["parameters"].([]interface{}); ok {
				for _, prm := range bp {
					if pm2, ok := prm.(map[string]interface{}); ok {
						if in, _ := pm2["in"].(string); in == "body" {
							schema, _ := pm2["schema"].(map[string]interface{})
							if body := sampleFromSchema(schema); body != nil {
								req.Body = body
								req.Headers = append(req.Headers, "Content-Type: application/json")
							}
						}
					}
				}
			}
			plan.Requests = append(plan.Requests, req)
		}
	}
	if plan.BaseURL == "" {
		plan.Warnings = append(plan.Warnings, "no host found — use --base-url to set the target")
	}
	if len(plan.Requests) == 0 {
		return nil, fmt.Errorf("no operations found in spec")
	}
	return plan, nil
}

func opSummary(opm map[string]interface{}, method string) string {
	if v, ok := opm["summary"].(string); ok && v != "" {
		return v
	}
	if v, ok := opm["operationId"].(string); ok && v != "" {
		return v
	}
	return strings.ToUpper(method)
}

func paramList(v interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	if refs, ok := v.([]interface{}); ok {
		for _, r := range refs {
			if m, ok := r.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func exampleValue(prm map[string]interface{}) string {
	if v, ok := prm["example"].(string); ok && v != "" {
		return v
	}
	if v, ok := prm["default"].(string); ok && v != "" {
		return v
	}
	if v, ok := prm["x-example"].(string); ok && v != "" {
		return v
	}
	return ""
}

func buildRequestBody(rb map[string]interface{}) ([]byte, string) {
	content, _ := rb["content"].(map[string]interface{})
	if content == nil {
		return nil, ""
	}
	if js, ok := content["application/json"].(map[string]interface{}); ok {
		schema, _ := js["schema"].(map[string]interface{})
		body := sampleFromSchema(schema)
		return body, "application/json"
	}
	for ct, spec := range content {
		if m, ok := spec.(map[string]interface{}); ok {
			if schema, ok := m["schema"].(map[string]interface{}); ok {
				body := sampleFromSchema(schema)
				if body != nil {
					return body, ct
				}
			}
		}
	}
	return nil, ""
}

func sampleFromSchema(schema map[string]interface{}) []byte {
	if schema == nil {
		return nil
	}
	if ex, ok := schema["example"].(map[string]interface{}); ok {
		b, _ := json.Marshal(ex)
		return b
	}
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		out := map[string]interface{}{}
		for name, pv := range props {
			ps, _ := pv.(map[string]interface{})
			out[name] = schemaValue(ps)
		}
		b, err := json.Marshal(out)
		if err != nil {
			return nil
		}
		return b
	}
	return nil
}

func schemaValue(s map[string]interface{}) interface{} {
	if s == nil {
		return nil
	}
	if v, ok := s["example"]; ok {
		return v
	}
	if v, ok := s["default"]; ok {
		return v
	}
	switch t, _ := s["type"].(string); t {
	case "string":
		if f, ok := s["format"].(string); ok {
			switch f {
			case "email":
				return "user@example.com"
			case "uuid":
				return "00000000-0000-0000-0000-000000000000"
			case "date-time":
				return "2026-01-01T00:00:00Z"
			}
		}
		return "string"
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		items, _ := s["items"].(map[string]interface{})
		return []interface{}{schemaValue(items)}
	case "object":
		out := map[string]interface{}{}
		if props, ok := s["properties"].(map[string]interface{}); ok {
			for n, pv := range props {
				ps, _ := pv.(map[string]interface{})
				out[n] = schemaValue(ps)
			}
		}
		return out
	}
	return nil
}
