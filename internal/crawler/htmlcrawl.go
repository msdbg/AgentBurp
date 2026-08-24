package crawler

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

type Form struct {
	Action   string            `json:"action"`
	Method   string            `json:"method"`
	Fields   []FormField       `json:"fields"`
	FieldMap map[string]string `json:"-"`
}

type FormField struct {
	Name    string   `json:"name"`
	Type    string   `json:"type,omitempty"`
	Value   string   `json:"value,omitempty"`
	Options []string `json:"options,omitempty"`
}

func ExtractLinks(baseURL string, body []byte) []string {
	seen := map[string]bool{}
	var out []string
	add := func(href string) {
		if u := ResolveLink(baseURL, href); u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}

	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return out
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			switch tok.Data {
			case "a", "link", "area":
				if v := attr(tok, "href"); v != "" {
					add(v)
				}
			case "script", "img", "iframe", "source", "embed":
				if v := attr(tok, "src"); v != "" {
					add(v)
				}
			case "form":
				if v := attr(tok, "action"); v != "" {
					add(v)
				}
			}
		}
	}
}

func ExtractInlineScripts(body []byte) []string {
	var out []string
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return out
		case html.StartTagToken:
			tok := z.Token()
			if tok.Data != "script" {
				continue
			}
			if attr(tok, "src") != "" {
				continue
			}
			if nt := z.Next(); nt == html.TextToken {
				text := strings.TrimSpace(z.Token().Data)
				if text != "" {
					out = append(out, text)
				}
			}
		}
	}
}

func attr(tok html.Token, name string) string {
	for _, a := range tok.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

func ExtractForms(baseURL string, body []byte) []Form {
	var forms []Form
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return forms
		case html.StartTagToken:
			tok := z.Token()
			if tok.Data != "form" {
				continue
			}
			f := Form{
				Method:   strings.ToUpper(attr(tok, "method")),
				FieldMap: map[string]string{},
			}
			if f.Method == "" {
				f.Method = "GET"
			}
			action := attr(tok, "action")
			if action == "" {
				action = baseURL
			}
			f.Action = ResolveLink(baseURL, action)
			if f.Action == "" {
				f.Action = baseURL
			}
			depth := 1
			for depth > 0 {
				nt := z.Next()
				switch nt {
				case html.ErrorToken:
					depth = 0
				case html.StartTagToken, html.SelfClosingTagToken:
					ft := z.Token()
					if ft.Data == "form" {
						depth++
					}
					switch ft.Data {
					case "input":
						name := attr(ft, "name")
						if name == "" {
							continue
						}
						typ := attr(ft, "type")
						val := attr(ft, "value")
						if strings.EqualFold(typ, "submit") || strings.EqualFold(typ, "button") ||
							strings.EqualFold(typ, "image") {
							continue
						}
						f.Fields = append(f.Fields, FormField{Name: name, Type: typ, Value: val})
						if _, ok := f.FieldMap[name]; !ok {
							f.FieldMap[name] = val
						}
					case "select":
						name := attr(ft, "name")
						if name == "" {
							continue
						}
						opts := collectSelectOptions(z)
						ff := FormField{Name: name, Type: "select"}
						for _, o := range opts {
							ff.Options = append(ff.Options, o.Value)
							if o.Selected && ff.Value == "" {
								ff.Value = o.Value
							}
						}
						f.Fields = append(f.Fields, ff)
						if _, ok := f.FieldMap[name]; !ok {
							f.FieldMap[name] = ff.Value
						}
					case "textarea":
						name := attr(ft, "name")
						if name == "" {
							continue
						}
						val := ""
						if nt == html.StartTagToken {
							if zt := z.Next(); zt == html.TextToken {
								val = strings.TrimSpace(z.Token().Data)
							}
						}
						f.Fields = append(f.Fields, FormField{Name: name, Type: "textarea", Value: val})
						if _, ok := f.FieldMap[name]; !ok {
							f.FieldMap[name] = val
						}
					}
				case html.EndTagToken:
					ft := z.Token()
					if ft.Data == "form" {
						depth--
					}
				}
			}
			forms = append(forms, f)
		}
	}
}

type selectOption struct {
	Value    string
	Selected bool
}

func collectSelectOptions(z *html.Tokenizer) []selectOption {
	var opts []selectOption
	depth := 1
	for depth > 0 {
		nt := z.Next()
		switch nt {
		case html.ErrorToken:
			return opts
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			if tok.Data == "select" {
				depth++
			}
			if tok.Data == "option" {
				val := attr(tok, "value")
				selected := false
				for _, a := range tok.Attr {
					if strings.EqualFold(a.Key, "selected") {
						selected = true
						break
					}
				}
				opts = append(opts, selectOption{Value: val, Selected: selected})
			}
		case html.EndTagToken:
			if z.Token().Data == "select" {
				depth--
			}
		}
	}
	return opts
}

func FormRequest(f Form) (method string, url string, body []byte) {
	sep := "?"
	if strings.Contains(f.Action, "?") {
		sep = "&"
	}
	var pairs []string
	for _, field := range f.Fields {
		pairs = append(pairs, urlEncode(field.Name)+"="+urlEncode(field.Value))
	}
	if f.Method == "POST" {
		return "POST", f.Action, []byte(strings.Join(pairs, "&"))
	}
	query := strings.Join(pairs, "&")
	if query != "" {
		return "GET", f.Action + sep + query, nil
	}
	return "GET", f.Action, nil
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.' || r == '~':
			b.WriteRune(r)
		case r == ' ':
			b.WriteString("+")
		default:
			b.WriteString("%" + strings.ToUpper(toHex(r)))
		}
	}
	return b.String()
}

func toHex(r rune) string {
	const hexDigits = "0123456789ABCDEF"
	var out []byte
	n := int(r)
	for n > 0 {
		out = append([]byte{hexDigits[n%16]}, out...)
		n /= 16
	}
	if len(out) == 0 {
		out = []byte{'0'}
	}
	return string(out)
}
