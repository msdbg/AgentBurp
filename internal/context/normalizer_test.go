package context

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/api/users/123", "/api/users/{id}"},
		{"/api/users/123/orders/456", "/api/users/{id}/orders/{id}"},
		{"/api/posts/9f8c1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b", "/api/posts/{uuid}"},
		{"/api/objects/507f1f77bcf86cd799439011", "/api/objects/{hash}"},
		{"/api/tokens/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "/api/tokens/{param}"},
		{"/api/users/special", "/api/users/special"},
		{"/", "/"},
		{"/static/app.js", "/static/app.js"},
		{"/api/v1/users/999", "/api/v1/users/{id}"},
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/users/{id}", "/api/users"},
		{"/api/users", "/api/users"},
		{"/api/posts/{uuid}", "/api/posts"},
		{"/api/items/{param}", "/api/items"},
		{"/api/tokens/{hash}/validate", "/api/tokens/{hash}/validate"},
	}
	for _, c := range cases {
		if got := CanonicalPath(c.in); got != c.want {
			t.Errorf("CanonicalPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTemplateFits(t *testing.T) {
	cases := []struct {
		template, path string
		want           bool
	}{
		{"/api/users/{id}", "/api/users/42", true},
		{"/api/users/{id}", "/api/users/special", true},
		{"/api/users/{id}", "/api/users/42/extra", false},
		{"/api/users/{id}", "/api/orders/42", false},
		{"/api/users/list", "/api/users/list", true},
		{"/api/users/list", "/api/users/42", false},
		{"/api/users/{uuid}", "/api/users/9f8c1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b", true},
	}
	for _, c := range cases {
		if got := TemplateFits(c.template, c.path); got != c.want {
			t.Errorf("TemplateFits(%q, %q) = %v, want %v", c.template, c.path, got, c.want)
		}
	}
}

func TestSegmentCount(t *testing.T) {
	if got := SegmentCount("/api/users/{id}"); got != 3 {
		t.Errorf("SegmentCount = %d, want 3", got)
	}
	if got := SegmentCount("/"); got != 0 {
		t.Errorf("SegmentCount = %d, want 0", got)
	}
}
