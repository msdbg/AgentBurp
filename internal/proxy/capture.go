package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	px "github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/msdbg/AgentBurp/internal/context"
	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

func hashBody(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

func (c *CaptureAddon) saveExchange(f *px.Flow) error {
	req := f.Request
	resp := f.Response
	conn := c.db.Conn()
	reqHeaders := headersToSlice(req.Header)
	reqHeadersJSON, _ := json.Marshal(reqHeaders)
	port := req.URL.Port()
	portNum := 80
	if port != "" {
		portNum, _ = strconv.Atoi(port)
	} else if req.URL.Scheme == "https" {
		portNum = 443
	}

	reqID := core.NewID("req")
	now := core.TimestampNow()

	bodyHash := ""
	var bodyBlob []byte
	if len(req.Body) > 0 {
		bodyBlob = req.Body
		bodyHash = hashBody(bodyBlob)
	}

	host := req.URL.Hostname()
	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	_, err := conn.Exec(`
		INSERT INTO requests
		  (id, project_id, source, method, url, host, port, scheme, path,
		   query_string, headers_json, body_blob, body_hash, created_at)
		VALUES (?, ?, 'proxy', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reqID, c.cfg.ProjectID,
		req.Method, req.URL.String(), host, portNum, req.URL.Scheme,
		path, req.URL.RawQuery,
		string(reqHeadersJSON), bodyBlob, bodyHash, now,
	)
	if err != nil {
		return err
	}
	respHeaders := headersToSlice(resp.Header)
	respHeadersJSON, _ := json.Marshal(respHeaders)
	respID := core.NewID("resp")

	var respBodyBlob []byte
	respBodyHash := ""
	if len(resp.Body) > 0 {
		respBodyBlob = resp.Body
		respBodyHash = hashBody(respBodyBlob)
	}

	ct := resp.Header.Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}

	_, err = conn.Exec(`
		INSERT INTO responses
		  (id, request_id, status_code, reason, headers_json, body_blob, body_hash,
		   content_type, length_bytes, time_ms, created_at)
		VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?)`,
		respID, reqID,
		resp.StatusCode,
		string(respHeadersJSON), respBodyBlob, respBodyHash,
		ct, len(respBodyBlob),
		time.Since(f.StartTime).Milliseconds(),
		now,
	)
	if err != nil {
		_ = err
	}

	c.audit.LogRequestSent(reqID, "proxy")

	if !c.cfg.SilentMode {
		fmt.Printf("[proxy] %s %s → %d\n", req.Method, req.URL.String(), resp.StatusCode)
	}

	go context.ExtractEndpoint(conn, c.cfg.ProjectID, reqID, host, req.Method, path, req.URL.RawQuery, req.Header, req.Body)
	go context.UpdateEndpointResponse(conn, reqID, resp.StatusCode, ct)

	return nil
}

func matchesRule(m RuleMatch, req *px.Request) bool {
	if m.Host != "" && !strings.EqualFold(req.URL.Hostname(), m.Host) {
		return false
	}
	if m.Path != "" && !strings.HasPrefix(req.URL.Path, m.Path) {
		return false
	}
	if m.Method != "" && !strings.EqualFold(req.Method, m.Method) {
		return false
	}
	return true
}

func headersToSlice(h http.Header) []models.Header {
	var out []models.Header
	for k, vals := range h {
		for _, v := range vals {
			out = append(out, models.Header{Name: k, Value: v})
		}
	}
	return out
}

func CACertPath(projectDir string) string {
	return projectDir + "/ca/mitmproxy-ca-cert.pem"
}

var _ = models.Header{}
