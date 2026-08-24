package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProfileJSONLogin(t *testing.T) {
	path := writeProfile(t, `
name: admin_login
type: json_login
url: https://app.example.com/api/login
method: POST
body:
  username: ${TEST_USER}
  password: testpass
capture:
  cookies: true
  headers:
    - Authorization
`)
	os.Setenv("TEST_USER", "admin")
	defer os.Unsetenv("TEST_USER")

	p, err := LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "json_login" || p.URL == "" {
		t.Errorf("profile parse wrong: %+v", p)
	}
	sub := p.Substitute()
	if sub.Body["username"] != "admin" {
		t.Errorf("env substitution failed: %+v", sub.Body)
	}
}

func TestLoadProfileFormLogin(t *testing.T) {
	path := writeProfile(t, `
name: form_login
type: form_login
url: https://app.example.com/login
form:
  username: admin
  password: secret
`)
	if _, err := LoadProfile(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProfileValidation(t *testing.T) {
	path := writeProfile(t, `
name: bad
type: unknown_type
url: https://x.test/
`)
	_, err := LoadProfile(path)
	if err == nil {
		t.Error("expected validation error for unknown type")
	}

	path2 := writeProfile(t, `
name: bad2
type: json_login
`)
	_, err = LoadProfile(path2)
	if err == nil {
		t.Error("expected validation error for missing url")
	}
}

func TestBuildLoginBodyFormAcceptsBodyFields(t *testing.T) {
	p := &AuthProfile{Name: "wg", Type: "form_login", URL: "http://x/login",
		Body: map[string]interface{}{"username": "abuser", "password": "Abuser123!"}}
	b, ct, err := buildLoginBody(p)
	if err != nil {
		t.Fatal(err)
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("wrong content type: %s", ct)
	}
	if string(b) != "password=Abuser123%21&username=abuser" && string(b) != "username=abuser&password=Abuser123%21" {
		t.Errorf("wrong form body: %q", b)
	}

	p2 := &AuthProfile{Name: "wg2", Type: "form_login", URL: "http://x/login",
		Form: map[string]string{"a": "1"}, Body: map[string]interface{}{"b": "2"}}
	b2, _, err := buildLoginBody(p2)
	if err != nil || string(b2) != "a=1" {
		t.Errorf("form: should take precedence, got %q err %v", b2, err)
	}

	p3 := &AuthProfile{Name: "wg3", Type: "form_login", URL: "http://x/login"}
	if _, _, err := buildLoginBody(p3); err == nil {
		t.Error("expected error for empty form profile")
	}
}

func TestLooksLikeLoginPage(t *testing.T) {
	login := []byte(`<html><head><title>Login Page</title></head><body>
		<form method="post" action="/login"><input name="username"><input type="password" name="password"><button>Sign in</button></form></body></html>`)
	if !looksLikeLoginPage(login, "text/html;charset=UTF-8") {
		t.Error("login page should be detected")
	}
	if looksLikeLoginPage([]byte(`{"error":"bad credentials"}`), "application/json") {
		t.Error("JSON error body should not be detected as login page")
	}
	if looksLikeLoginPage([]byte(`<html><body><h1>Welcome</h1></body></html>`), "text/html") {
		t.Error("dashboard should not be detected as login page")
	}
}

func TestStaticProfiles(t *testing.T) {
	path := writeProfile(t, `
name: svc_token
type: bearer
token: ${TEST_TOKEN}
`)
	os.Setenv("TEST_TOKEN", "abc123")
	defer os.Unsetenv("TEST_TOKEN")
	p, err := LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Substitute().Token != "abc123" {
		t.Error("bearer token substitution failed")
	}
}

func TestLookupPath(t *testing.T) {
	obj := map[string]interface{}{
		"data": map[string]interface{}{
			"access_token": "tok123",
		},
		"count": float64(3),
	}
	if v, ok := lookupPath(obj, "data.access_token"); !ok || v != "tok123" {
		t.Errorf("lookupPath data.access_token = %q, %v", v, ok)
	}
	if v, ok := lookupPath(obj, "count"); !ok || v != "3" {
		t.Errorf("lookupPath count = %q, %v", v, ok)
	}
	if _, ok := lookupPath(obj, "missing.key"); ok {
		t.Error("expected missing path to fail")
	}
}

func TestExtractTokensFromBody(t *testing.T) {
	body := []byte(`{"access_token":"jwt1","data":{"token":"inner"}}`)
	tokens := extractTokensFromBody(body, []string{"access_token", "data.token"})
	if tokens["access_token"] != "jwt1" {
		t.Errorf("access_token extraction wrong: %+v", tokens)
	}
	if tokens["Authorization"] != "Bearer jwt1" {
		t.Errorf("authorization derivation wrong: %+v", tokens)
	}
	if tokens["token"] != "inner" {
		t.Errorf("nested token extraction wrong: %+v", tokens)
	}
}
