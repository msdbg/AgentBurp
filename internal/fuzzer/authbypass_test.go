package fuzzer

import (
	"net/http"
	"strings"
	"testing"
)

func TestAuthBypassSignalFlagsSQLiLoginBypass(t *testing.T) {
	pos, _ := ParsePosition("body.email")
	r := &Runner{
		base: &Request{
			Method: "POST",
			URL:    "http://example.com/rest/user/login",
			Body:   []byte(`{"email":"admin@example.com","password":"x"}`),
		},
		positions: []*Position{pos},
		baseline: &Baseline{
			Status:   200,
			Artifact: "eyJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoiZnVsbC1hY2Nlc3MifQ.baselinesig",
		},
	}
	body := []byte(`{"authentication":{"token":"eyJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoiZnVsbC1hY2Nlc3MifQ.newsig"}}`)
	resp := &http.Response{Header: http.Header{}}
	reason := r.authBypassSignal(map[string]string{"body.email": "' OR 1=1--"}, body, resp)
	if !strings.Contains(reason, "authentication artifact issued for modified input") {
		t.Errorf("expected bypass signal, got: %q", reason)
	}
	if !strings.Contains(reason, "high") {
		t.Errorf("injection payload should be high confidence, got: %q", reason)
	}
}

func TestAuthBypassSignalIgnoresLegitCredentials(t *testing.T) {
	pos, _ := ParsePosition("body.email")
	r := &Runner{
		base: &Request{
			Method: "POST",
			URL:    "http://example.com/rest/user/login",
			Body:   []byte(`{"email":"admin@example.com","password":"x"}`),
		},
		positions: []*Position{pos},
		baseline: &Baseline{
			Status:   200,
			Artifact: "eyJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoiZnVsbC1hY2Nlc3MifQ.baselinesig",
		},
	}
	body := []byte(`{"authentication":{"token":"eyJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoiZnVsbC1hY2Nlc3MifQ.baselinesig"}}`)
	resp := &http.Response{Header: http.Header{}}
	if reason := r.authBypassSignal(map[string]string{"body.email": "' OR 1=1--"}, body, resp); reason != "" {
		t.Errorf("identical artifact must not be flagged, got: %q", reason)
	}
	if reason := r.authBypassSignal(map[string]string{"body.email": "' OR 1=1--"}, body, resp); reason != "" {
		t.Errorf("identical artifact must not be flagged, got: %q", reason)
	}
}

func TestAuthBypassSignalIgnoresRejectedResponses(t *testing.T) {
	pos, _ := ParsePosition("body.solution")
	r := &Runner{
		base: &Request{
			Method: "POST",
			URL:    "http://example.com/challenge/challenge-0",
			Body:   []byte(`solution=x&_csrf=tok`),
		},
		positions: []*Position{pos},
		baseline: &Baseline{
			Status:   403,
			Artifact: "JSESSIONID=baseline; Path=/; HttpOnly",
		},
	}
	body := []byte(`<html>Invalid CSRF token</html>`)
	h := http.Header{}
	h.Add("Set-Cookie", "JSESSIONID=brandnew; Path=/; HttpOnly")
	resp := &http.Response{StatusCode: 403, Header: h}
	if reason := r.authBypassSignal(map[string]string{"body.solution": "' OR 1=1--"}, body, resp); reason != "" {
		t.Errorf("rejected response must not be flagged as bypass, got: %q", reason)
	}

	resp = &http.Response{StatusCode: 200, Header: h}
	r2 := &Runner{
		base: &Request{
			Method: "POST",
			URL:    "http://example.com/login",
			Body:   []byte(`email=admin@example.com&password=x`),
		},
		positions: []*Position{pos},
		baseline: &Baseline{
			Status:   200,
			Artifact: "JSESSIONID=baseline",
		},
	}
	if reason := r2.authBypassSignal(map[string]string{"body.email": "' OR 1=1--"}, body, resp); !strings.Contains(reason, "authentication artifact issued") {
		t.Errorf("successful response with new credential should be flagged, got: %q", reason)
	}
}

func TestAuthBypassSignalIgnoresGETTokenMinting(t *testing.T) {
	pos, _ := ParsePosition("query.callback")
	r := &Runner{
		base: &Request{
			Method: "GET",
			URL:    "http://example.com/csrf-token?callback=x",
			Body:   nil,
		},
		positions: []*Position{pos},
		baseline: &Baseline{
			Status:   200,
			Artifact: "abc123def456",
		},
	}
	body := []byte(`{"token":"zzz999yyy888"}`)
	resp := &http.Response{Header: http.Header{}}
	if reason := r.authBypassSignal(map[string]string{"query.callback": "y"}, body, resp); reason != "" {
		t.Errorf("GET token-minting endpoint must not be flagged as bypass, got: %q", reason)
	}
}

func TestAuthArtifactJWT(t *testing.T) {
	body := []byte(`{"authentication":{"token":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0eXBlIjoiZnVsbC1hY2Nlc3MifQ."}}`)
	a := authArtifact(body, http.Header{})
	if !strings.HasPrefix(a, "eyJhbGci") {
		t.Errorf("JWT artifact not extracted: %q", a)
	}
}

func TestAuthArtifactSessionCookie(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "JSESSIONID=abc123; Path=/; HttpOnly")
	a := authArtifact(nil, h)
	if a != "JSESSIONID=abc123" {
		t.Errorf("session cookie artifact not extracted: %q", a)
	}
}

func TestOriginalValue(t *testing.T) {
	pos, _ := ParsePosition("body.username")
	v := originalValue(testBase(), pos)
	if v != "admin" {
		t.Errorf("body original value: %q", v)
	}
	posQ, _ := ParsePosition("query.role")
	if v := originalValue(testBase(), posQ); v != "user" {
		t.Errorf("query original value: %q", v)
	}
}
