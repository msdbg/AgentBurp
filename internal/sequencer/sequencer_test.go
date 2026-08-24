package sequencer

import (
	"encoding/json"
	"testing"

	"github.com/msdbg/AgentBurp/internal/core"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(nil)
	if r.Rating != "n/a" {
		t.Errorf("expected n/a rating, got %q", r.Rating)
	}
	r = Analyze([]string{"", "  "})
	if r.Rating != "n/a" {
		t.Errorf("expected n/a rating for blank tokens, got %q", r.Rating)
	}
}

func TestAnalyzeSequential(t *testing.T) {
	tokens := []string{"1000", "1001", "1002", "1003", "1004", "1005"}
	r := Analyze(tokens)
	if !r.Sequential {
		t.Error("expected sequential detection")
	}
	if r.PredictedNext != "1006" {
		t.Errorf("expected predicted next 1006, got %q", r.PredictedNext)
	}
	if r.Rating != "very-weak" {
		t.Errorf("expected very-weak rating, got %q", r.Rating)
	}
	if r.DuplicateTokens != 0 {
		t.Errorf("no duplicates expected, got %d", r.DuplicateTokens)
	}
}

func TestAnalyzeDuplicates(t *testing.T) {
	r := Analyze([]string{"abc123", "abc123", "abc123"})
	if r.UniqueTokens != 1 || r.DuplicateTokens != 2 {
		t.Errorf("dup detection wrong: %d unique / %d dup", r.UniqueTokens, r.DuplicateTokens)
	}
	if len(r.Notes) == 0 {
		t.Error("expected notes about duplicates")
	}
}

func TestAnalyzeStrongRandom(t *testing.T) {
	tokens := []string{
		"a3f0c9d2e1b84756f0c9d2e1b84756f0",
		"b4a1d0e3f2c95867a1d0e3f2c95867a1",
		"c5b2e1f4a3d06978b2e1f4a3d06978b2",
		"d6c3f2a5b4e17a89c3f2a5b4e17a89c3",
		"e7d4a3b6c5f28b9ad4a3b6c5f28b9ad4",
	}
	r := Analyze(tokens)
	if r.Charset != "hex" {
		t.Errorf("expected hex charset, got %q", r.Charset)
	}
	if r.Sequential {
		t.Error("random hex should not be sequential")
	}
	if r.Rating != "strong" {
		t.Errorf("expected strong rating, got %q (entropy %.3f)", r.Rating, r.EntropyPerChar)
	}
}

func TestAnalyzeWeak(t *testing.T) {
	r := Analyze([]string{"tok123", "tok456", "tok789"})
	if r.Rating != "weak" {
		t.Errorf("expected weak rating for short tokens, got %q", r.Rating)
	}
}

func TestAnalyzeUUID(t *testing.T) {
	r := Analyze([]string{
		"3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"8c1a4f2e-9b34-4a56-8d7e-f123456789ab",
	})
	if r.Charset != "uuid" {
		t.Errorf("expected uuid charset, got %q", r.Charset)
	}
}

func TestAnalyzeNormalization(t *testing.T) {
	r := Analyze([]string{`"tok123"`, "'tok456'"})
	if r.UniqueTokens != 2 {
		t.Errorf("quoted tokens should be normalized, got %d unique", r.UniqueTokens)
	}
}

func TestAnalyzeBase64(t *testing.T) {
	r := Analyze([]string{
		"dGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgdG9rZW4gdmFsdWU=",
		"c2Vjb25kIGJhc2U2NCB0b2tlbiB3aXRoIG1vcmUgZGF0YSE=",
	})
	if r.Charset != "base64" {
		t.Errorf("expected base64 charset, got %q", r.Charset)
	}
}

func TestMonotonicIrregular(t *testing.T) {
	r := Analyze([]string{"100", "250", "400", "900"})
	if r.Sequential {
		t.Error("irregular steps should not be sequential")
	}
	if !r.Monotonic {
		t.Error("expected monotonic detection")
	}
}

func TestCaptureTokens(t *testing.T) {
	db, err := core.Open(t.TempDir() + "/seq.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	proj, err := core.NewProjectStore(db).Create("seq-proj")
	if err != nil {
		t.Fatal(err)
	}

	now := core.TimestampNow()
	for _, tc := range []struct {
		headers string
		body    string
	}{
		{`[{"name":"Set-Cookie","value":"sid=abc123; Path=/"}]`, `{"access_token":"tok123"}`},
		{`[]`, `{"access_token":"tok456"}`},
		{`[]`, `{"other":"x"}`},
	} {
		reqID := core.NewID("req")
		respID := core.NewID("resp")
		db.Conn().Exec(`
			INSERT INTO requests (id, project_id, source, method, url, host, port, scheme, path,
				query_string, headers_json, body_blob, body_hash, session_id, note, created_at)
			VALUES (?, ?, 'proxy', 'GET', 'http://x/', 'x', 80, 'http', '/', '',
				'[]', NULL, '', '', '', ?)`, reqID, proj.ID, now)
		db.Conn().Exec(`
			INSERT INTO responses (id, request_id, status_code, reason, headers_json, body_blob,
				body_hash, content_type, length_bytes, time_ms, created_at)
			VALUES (?, ?, 200, '', ?, ?, '', 'application/json', 0, 0, ?)`,
			respID, reqID, tc.headers, []byte(tc.body), now)
	}

	bodyTokens, err := CaptureTokens(db.Conn(), proj.ID, "body", "access_token")
	if err != nil {
		t.Fatal(err)
	}
	if len(bodyTokens) != 2 || bodyTokens[0] != "tok123" || bodyTokens[1] != "tok456" {
		t.Errorf("body capture wrong: %v", bodyTokens)
	}

	headerTokens, err := CaptureTokens(db.Conn(), proj.ID, "header", "Set-Cookie")
	if err != nil {
		t.Fatal(err)
	}
	if len(headerTokens) != 1 || headerTokens[0] != "sid=abc123; Path=/" {
		t.Errorf("header capture wrong: %v", headerTokens)
	}

	cookieTokens, err := CaptureTokens(db.Conn(), proj.ID, "cookie", "sid")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookieTokens) != 1 || cookieTokens[0] != "abc123" {
		t.Errorf("cookie capture wrong: %v", cookieTokens)
	}
}

var _ = json.Marshal
