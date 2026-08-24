package crawler

import (
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://example.com/a#frag", "http://example.com/a"},
		{"http://example.com/a?b=2&a=1", "http://example.com/a?a=1&b=2"},
		{"https://example.com:443/x", "https://example.com/x"},
		{"http://example.com:80/x", "http://example.com/x"},
		{"http://example.com/a?x=1&x=2", "http://example.com/a?x=1&x=2"},
	}
	for _, c := range cases {
		if got := NormalizeURL(c.in); got != c.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveLink(t *testing.T) {
	base := "http://example.com/dir/page.html"
	cases := []struct {
		href, want string
	}{
		{"/api/users", "http://example.com/api/users"},
		{"../other", "http://example.com/other"},
		{"sub/page", "http://example.com/dir/sub/page"},
		{"#anchor", ""},
		{"javascript:void(0)", ""},
		{"mailto:a@b.c", ""},
		{"//cdn.example.com/x.js", "http://cdn.example.com/x.js"},
	}
	for _, c := range cases {
		if got := ResolveLink(base, c.href); got != c.want {
			t.Errorf("ResolveLink(%q, %q) = %q, want %q", base, c.href, got, c.want)
		}
	}
}

func TestIsStaticResource(t *testing.T) {
	for _, u := range []string{"http://e.com/a.png", "http://e.com/x.css", "http://e.com/v.mp4", "http://e.com/f.zip"} {
		if !IsStaticResource(u) {
			t.Errorf("expected static: %s", u)
		}
	}
	for _, u := range []string{"http://e.com/page", "http://e.com/a.js?x=1", "http://e.com/api/1"} {
		if IsStaticResource(u) {
			t.Errorf("expected non-static: %s", u)
		}
	}
}

const sampleHTML = `<html>
<body>
  <a href="/api/users">Users</a>
  <a href="/api/users/1">User 1</a>
  <a href="#top">Skip</a>
  <a href="javascript:void(0)">Bad</a>
  <a href="https://other.example.com/away">External</a>
  <script src="/static/app.js"></script>
  <img src="/static/logo.png">
  <link rel="stylesheet" href="/static/site.css">
  <script>
    fetch('/api/profile');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
  </script>
  <form method="POST" action="/api/login">
    <input type="hidden" name="csrf" value="tok1">
    <input type="text" name="username">
    <input type="submit" value="Go">
    <select name="role">
      <option value="user">User</option>
      <option value="admin" selected>Admin</option>
    </select>
    <textarea name="bio">hello</textarea>
  </form>
</body>
</html>`

func TestExtractLinks(t *testing.T) {
	base := "http://example.com/"
	links := ExtractLinks(base, []byte(sampleHTML))
	joined := strings.Join(links, "\n")
	for _, want := range []string{
		"http://example.com/api/users",
		"http://example.com/api/users/1",
		"http://example.com/static/app.js",
		"http://example.com/static/logo.png",
		"http://example.com/static/site.css",
		"http://example.com/api/login",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing link %s in:\n%s", want, joined)
		}
	}
	for _, bad := range []string{"javascript:", "#top", "mailto:"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unexpected link containing %s", bad)
		}
	}
	var jsURLs []string
	for _, script := range ExtractInlineScripts([]byte(sampleHTML)) {
		jsURLs = append(jsURLs, JSEndpointURLs(base, script)...)
	}
	jsJoined := strings.Join(jsURLs, "\n")
	for _, want := range []string{"http://example.com/api/profile", "http://example.com/api/upload"} {
		if !strings.Contains(jsJoined, want) {
			t.Errorf("missing JS endpoint %s in:\n%s", want, jsJoined)
		}
	}
}

func TestExtractForms(t *testing.T) {
	forms := ExtractForms("http://example.com/", []byte(sampleHTML))
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "POST" || f.Action != "http://example.com/api/login" {
		t.Errorf("form meta wrong: %+v", f)
	}
	if len(f.Fields) != 4 {
		t.Errorf("expected 4 fields, got %d: %+v", len(f.Fields), f.Fields)
	}
	if f.FieldMap["username"] != "" || f.FieldMap["csrf"] != "tok1" {
		t.Errorf("field defaults wrong: %v", f.FieldMap)
	}
	for _, ff := range f.Fields {
		if ff.Name == "role" && ff.Value != "admin" {
			t.Errorf("select default should be admin, got %q", ff.Value)
		}
		if ff.Name == "bio" && ff.Value != "hello" {
			t.Errorf("textarea value wrong: %q", ff.Value)
		}
	}

	method, u, body := FormRequest(f)
	if method != "POST" || u != "http://example.com/api/login" {
		t.Errorf("form request wrong: %s %s", method, u)
	}
	if !strings.Contains(string(body), "username=") || !strings.Contains(string(body), "csrf=tok1") {
		t.Errorf("form body wrong: %s", body)
	}
}

func TestExtractInlineScripts(t *testing.T) {
	scripts := ExtractInlineScripts([]byte(sampleHTML))
	if len(scripts) != 1 || !strings.Contains(scripts[0], "fetch('/api/profile')") {
		t.Errorf("inline script extraction wrong: %v", scripts)
	}
}

func TestExtractJSPaths(t *testing.T) {
	js := `
const base = "/api/v2";
fetch("/api/profile");
xhr.open("POST", "/admin/users");
axios.get('/api/users/1');
import("/static/chunk-abc.js");
navigator.sendBeacon("/api/telemetry");
`
	paths := ExtractJSPaths(js)
	joined := strings.Join(paths, "\n")
	for _, want := range []string{"/api/profile", "/admin/users", "/api/users/1", "/api/telemetry", "/api/v2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing JS path %s in:\n%s", want, joined)
		}
	}
}

func TestExtractJSPathsSkipsTemplateLiterals(t *testing.T) {
	js := `
const url = this.hostServer + "/rest/products/search?q=" + e;
fetch(this.host + "/api/users/" + e);
axios.get('/api/Feedbacks');
navigator.sendBeacon(` + "`/${this.host}/rest/basket/${e}`" + `);
const x = ` + "`${this.hostServer}/rest/2fa/status`" + `;
`
	paths := ExtractJSPaths(js)
	joined := strings.Join(paths, "\n")
	if strings.Contains(joined, "${") {
		t.Errorf("template literal endpoints leaked into extraction:\n%s", joined)
	}
	if !strings.Contains(joined, "/api/Feedbacks") {
		t.Errorf("plain literal endpoint missing:\n%s", joined)
	}
}

func TestExtractJSPathsSkipsStaticAssetConcatenations(t *testing.T) {
	js := `
import(/* webpackChunkName: "api" */ "/static/js/api/auth/login");
const chunk = "/static/js/" + VIN + ".js";
const chunk2 = "/static/js/" + order_id;
const chunk3 = "/static/js/" + undefined;
loadScript("/static/js/v13.0.0");
import("/static/js/main.8c78208c.js");
import("/static/css/site.abc123.css");
fetch("/api/profile");
`
	paths := ExtractJSPaths(js)
	joined := strings.Join(paths, "\n")
	for _, banned := range []string{
		"/static/js/api/auth/login", "/static/js/VIN", "/static/js/order_id",
		"/static/js/undefined", "/static/js/v13.0.0",
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("static-asset concatenation leaked into extraction: %s\n%s", banned, joined)
		}
	}
	for _, want := range []string{"/api/profile"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing legit path %s in:\n%s", want, joined)
		}
	}
}

func TestJSEndpointURLs(t *testing.T) {
	urls := JSEndpointURLs("http://example.com/app", `fetch('/api/x'); fetch('/api/y')`)
	if len(urls) != 2 || urls[0] != "http://example.com/api/x" {
		t.Errorf("JS endpoint URLs wrong: %v", urls)
	}
}

func TestJSEndpointURLsResolveRelativeAgainstOrigin(t *testing.T) {
	js := `
const routes = {LOGIN:"api/auth/login", DASH:"api/v2/user/dashboard"};
const words = ["report","rest","restaurant","GET","undefined","order_id","content"];
fetch("api/telemetry");
`
	urls := JSEndpointURLs("http://example.com/static/js/main.8c78208c.js", js)
	joined := strings.Join(urls, "\n")
	for _, want := range []string{
		"http://example.com/api/auth/login",
		"http://example.com/api/v2/user/dashboard",
		"http://example.com/api/telemetry",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing root-resolved URL %s in:\n%s", want, joined)
		}
	}
	for _, banned := range []string{"/static/js/rest", "/static/js/GET", "/static/js/order_id", "/static/js/api/auth/login"} {
		if strings.Contains(joined, banned) {
			t.Errorf("JS-file-relative garbage leaked: %s\n%s", banned, joined)
		}
	}
}
