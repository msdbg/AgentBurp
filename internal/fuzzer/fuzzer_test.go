package fuzzer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePosition(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		kind string
		name string
	}{
		{"query.id", true, "query", "id"},
		{"body.username", true, "body", "username"},
		{"header.X-User-Id", true, "header", "X-User-Id"},
		{"cookie.csrf", true, "cookie", "csrf"},
		{"path.userId", true, "path", "userId"},
		{"query", false, "", ""},
		{"query.", false, "", ""},
		{"unknown.x", false, "", ""},
		{".x", false, "", ""},
	}
	for _, c := range cases {
		p, err := ParsePosition(c.in)
		if c.ok && (err != nil || p.Kind != c.kind || p.Name != c.name) {
			t.Errorf("ParsePosition(%q) = %+v, %v; want ok kind=%s name=%s", c.in, p, err, c.kind, c.name)
		}
		if !c.ok && err == nil {
			t.Errorf("ParsePosition(%q) should have failed", c.in)
		}
	}
}

func testBase() *Request {
	return &Request{
		Method: "POST",
		URL:    "http://example.com/api/users/42?role=user",
		Headers: []string{
			"Content-Type: application/json",
			"Cookie: session=abc; csrf=tok",
		},
		Body: []byte(`{"username":"admin","level":1}`),
	}
}

func TestApplyQueryPosition(t *testing.T) {
	base := testBase()
	pos, _ := ParsePosition("query.role")
	req, err := Apply(base, []*Position{pos}, map[string]string{"query.role": "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL, "role=admin") {
		t.Errorf("query position not applied: %s", req.URL)
	}
	if strings.Contains(req.URL, "role=user") {
		t.Errorf("old query value still present: %s", req.URL)
	}
}

func TestApplyBodyPosition(t *testing.T) {
	base := testBase()
	pos, _ := ParsePosition("body.username")
	req, err := Apply(base, []*Position{pos}, map[string]string{"body.username": "<script>alert(1)</script>"})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(req.Body, &obj); err != nil {
		t.Fatalf("result body not JSON: %v", err)
	}
	if obj["username"] != "<script>alert(1)</script>" {
		t.Errorf("body position not applied: %v", obj)
	}
}

func TestApplyNestedBodyPosition(t *testing.T) {
	base := &Request{Method: "POST", URL: "http://example.com/x", Body: []byte(`{"user":{"name":"a"}}`)}
	pos, _ := ParsePosition("body.user.name")
	req, err := Apply(base, []*Position{pos}, map[string]string{"body.user.name": "b"})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]map[string]string
	json.Unmarshal(req.Body, &obj)
	if obj["user"]["name"] != "b" {
		t.Errorf("nested body position not applied: %s", req.Body)
	}
}

func TestApplyHeaderAndCookiePosition(t *testing.T) {
	base := testBase()
	hpos, _ := ParsePosition("header.Authorization")
	cpos, _ := ParsePosition("cookie.csrf")
	req, err := Apply(base, []*Position{hpos, cpos}, map[string]string{
		"header.Authorization": "Bearer xyz",
		"cookie.csrf":          "pwned",
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range req.Headers {
		if strings.HasPrefix(h, "Authorization:") {
			found = true
			if h != "Authorization: Bearer xyz" {
				t.Errorf("header position wrong: %s", h)
			}
		}
	}
	if !found {
		t.Errorf("Authorization header not added")
	}
	for _, h := range req.Headers {
		if strings.HasPrefix(h, "Cookie:") && !strings.Contains(h, "csrf=pwned") {
			t.Errorf("cookie position not applied: %s", h)
		}
	}
}

func TestApplyPathPosition(t *testing.T) {
	base := testBase()
	pos, _ := ParsePosition("path.42")
	req, err := Apply(base, []*Position{pos}, map[string]string{"path.42": "99"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.URL, "/api/users/99") {
		t.Errorf("path position not applied: %s", req.URL)
	}
}

func TestApplyMultipartPosition(t *testing.T) {
	base := &Request{
		Method:  "POST",
		URL:     "http://example.com/upload",
		Headers: []string{"Content-Type: multipart/form-data; boundary=X"},
		Body:    []byte("--X\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nORIGINAL\r\n--X--"),
	}
	pos, _ := ParsePosition("body.file")
	req, err := Apply(base, []*Position{pos}, map[string]string{"body.file": "PWNED"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(req.Body), "PWNED") || strings.Contains(string(req.Body), "ORIGINAL") {
		t.Errorf("multipart position not applied: %q", req.Body)
	}
}

func TestCombosSniper(t *testing.T) {
	positions, _ := positions2("query.a", "query.b")
	sets := [][]string{{"1", "2"}}
	combos, err := Combos(positions, sets, Sniper)
	if err != nil {
		t.Fatal(err)
	}
	if len(combos) != 4 {
		t.Fatalf("sniper combos = %d, want 4", len(combos))
	}
	if combos[0][0] != "1" || combos[0][1] != "" || combos[3][1] != "2" {
		t.Errorf("sniper vectors wrong: %v", combos)
	}
}

func TestCombosBatteringRam(t *testing.T) {
	positions, _ := positions2("query.a", "query.b")
	combos, err := Combos(positions, [][]string{{"X", "Y"}}, BatteringRam)
	if err != nil {
		t.Fatal(err)
	}
	if len(combos) != 2 {
		t.Fatalf("battering-ram combos = %d, want 2", len(combos))
	}
	if combos[0][0] != "X" || combos[0][1] != "X" {
		t.Errorf("battering-ram vector wrong: %v", combos[0])
	}
}

func TestCombosPitchfork(t *testing.T) {
	positions, _ := positions2("query.a", "query.b")
	combos, err := Combos(positions, [][]string{{"1", "2", "3"}, {"x", "y"}}, Pitchfork)
	if err != nil {
		t.Fatal(err)
	}
	if len(combos) != 2 {
		t.Fatalf("pitchfork combos = %d, want 2 (zip to shortest)", len(combos))
	}
	if combos[1][0] != "2" || combos[1][1] != "y" {
		t.Errorf("pitchfork vector wrong: %v", combos[1])
	}
}

func TestCombosClusterBomb(t *testing.T) {
	positions, _ := positions2("query.a", "query.b")
	combos, err := Combos(positions, [][]string{{"1", "2"}, {"x", "y", "z"}}, ClusterBomb)
	if err != nil {
		t.Fatal(err)
	}
	if len(combos) != 6 {
		t.Fatalf("cluster-bomb combos = %d, want 6", len(combos))
	}
	if combos[5][0] != "2" || combos[5][1] != "z" {
		t.Errorf("cluster-bomb vector wrong: %v", combos[5])
	}
}

func TestCombosValidation(t *testing.T) {
	positions, _ := positions2("query.a", "query.b")
	if _, err := Combos(positions, [][]string{}, Sniper); err == nil {
		t.Error("sniper with no sets should fail")
	}
	if _, err := Combos(positions, [][]string{{"1"}}, Pitchfork); err == nil {
		t.Error("pitchfork with mismatched sets should fail")
	}
	if _, err := Combos(nil, [][]string{{"1"}}, Sniper); err == nil {
		t.Error("no positions should fail")
	}
}

func TestNumbers(t *testing.T) {
	vals, err := Numbers(1, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 5 || vals[4] != "5" {
		t.Errorf("numbers range wrong: %v", vals)
	}
	vals, err = Numbers(10, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 3 || vals[0] != "10" || vals[2] != "0" {
		t.Errorf("descending numbers wrong: %v", vals)
	}
	if _, err := Numbers(1, 5, 0); err == nil {
		t.Error("step 0 should fail")
	}
}

func TestMutationsNonEmpty(t *testing.T) {
	if len(Mutations()) < 30 {
		t.Errorf("mutation payloads too few: %d", len(Mutations()))
	}
}

func TestFilters(t *testing.T) {
	f := &Filters{StatusCodes: []int{500}, LengthGT: 100}
	body := make([]byte, 200)
	if matched, _ := f.Match(500, 200, body); !matched {
		t.Error("filter should match 500 + length>100")
	}
	if matched, _ := f.Match(200, 200, body); matched {
		t.Error("filter should not match 200")
	}
	if matched, _ := f.Match(500, 50, body); matched {
		t.Error("filter should not match short response")
	}
	g := &Filters{Grep: []string{"admin"}}
	if matched, _ := g.Match(200, 10, []byte("hello admin!")); !matched {
		t.Error("grep filter should match")
	}
	re := &Filters{Regex: `error.?[0-9]+`}
	if matched, _ := re.Match(200, 10, []byte("error42")); !matched {
		t.Error("regex filter should match")
	}
	if matched, _ := re.Match(200, 10, []byte("ok")); matched {
		t.Error("regex filter should not match")
	}
}

func positions2(a, b string) ([]*Position, error) {
	p1, err := ParsePosition(a)
	if err != nil {
		return nil, err
	}
	p2, err := ParsePosition(b)
	if err != nil {
		return nil, err
	}
	return []*Position{p1, p2}, nil
}
