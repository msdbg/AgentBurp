package differ

import (
	"testing"

	"github.com/msdbg/AgentBurp/internal/models"
)

func TestDiffRequestsIdentical(t *testing.T) {
	a := &models.Request{ID: "req_a", Method: "GET", URL: "https://x.test/a", Headers: []models.Header{{Name: "Host", Value: "x.test"}}, Body: []byte("hello")}
	b := &models.Request{ID: "req_b", Method: "GET", URL: "https://x.test/a", Headers: []models.Header{{Name: "Host", Value: "x.test"}}, Body: []byte("hello")}
	d := DiffRequests(a, b)
	if !d.Same {
		t.Errorf("expected identical, got %+v", d)
	}
}

func TestDiffRequestsMethodAndHeaders(t *testing.T) {
	a := &models.Request{Method: "GET", URL: "https://x.test/a", Headers: []models.Header{{Name: "Host", Value: "x.test"}}}
	b := &models.Request{Method: "POST", URL: "https://x.test/a", Headers: []models.Header{{Name: "Host", Value: "x.test"}, {Name: "X-Role", Value: "admin"}}}
	d := DiffRequests(a, b)
	if d.Same {
		t.Error("expected different")
	}
	if !d.Method.Changed || d.Method.Before != "GET" || d.Method.After != "POST" {
		t.Errorf("method diff wrong: %+v", d.Method)
	}
	if len(d.Headers.Added) != 1 || d.Headers.Added[0].Name != "X-Role" {
		t.Errorf("header add wrong: %+v", d.Headers)
	}
}

func TestDiffRequestsHeaderModifiedCaseInsensitive(t *testing.T) {
	a := &models.Request{Method: "GET", URL: "u", Headers: []models.Header{{Name: "Authorization", Value: "Bearer abc"}}}
	b := &models.Request{Method: "GET", URL: "u", Headers: []models.Header{{Name: "authorization", Value: "Bearer xyz"}}}
	d := DiffRequests(a, b)
	if len(d.Headers.Modified) != 1 {
		t.Errorf("expected 1 modified header, got %+v", d.Headers)
	}
}

func TestDiffResponsesStatus(t *testing.T) {
	a := &models.Response{StatusCode: 200, Headers: []models.Header{{Name: "Content-Type", Value: "text/html"}}}
	b := &models.Response{StatusCode: 403, Headers: []models.Header{{Name: "Content-Type", Value: "text/html"}}}
	d := DiffResponses(a, b)
	if d.Same {
		t.Error("expected different")
	}
	if !d.Status.Changed || d.Status.Before != "200" || d.Status.After != "403" {
		t.Errorf("status diff wrong: %+v", d.Status)
	}
}

func TestDiffResponsesBodyLines(t *testing.T) {
	a := &models.Response{StatusCode: 200, Body: []byte("line1\nline2\nline3\n")}
	b := &models.Response{StatusCode: 200, Body: []byte("line1\nCHANGED\nline3\n")}
	d := DiffResponses(a, b)
	if !d.Body.Changed {
		t.Error("expected body change")
	}
	hasDel, hasAdd := false, false
	for _, l := range d.Body.Lines {
		if l.Type == "del" && l.Line == "line2" {
			hasDel = true
		}
		if l.Type == "add" && l.Line == "CHANGED" {
			hasAdd = true
		}
	}
	if !hasDel || !hasAdd {
		t.Errorf("line diff incomplete: %+v", d.Body.Lines)
	}
}

func TestDiffResponsesBodyIdentical(t *testing.T) {
	a := &models.Response{StatusCode: 200, Body: []byte("same body\n")}
	b := &models.Response{StatusCode: 200, Body: []byte("same body\n")}
	d := DiffResponses(a, b)
	if d.Body.Changed {
		t.Error("body should be unchanged")
	}
}
