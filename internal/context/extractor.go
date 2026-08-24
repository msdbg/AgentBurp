package context

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/msdbg/AgentBurp/internal/core"
)

func ExtractEndpoint(db *sql.DB, projectID, reqID, host, method, path, queryString string, headers http.Header, body []byte) {
	template := NormalizePath(path)
	canonical := CanonicalPath(template)
	now := core.TimestampNow()

	epID, err := findEndpoint(db, projectID, host, method, template, path)
	if err != nil {
		epID = core.NewID("ep")
		statusJSON, _ := json.Marshal([]int{})
		ctJSON, _ := json.Marshal([]string{})
		db.Exec(`
			INSERT INTO endpoints
			  (id, project_id, host, method, path_template, canonical_path,
			   first_seen, last_seen, request_count, observed_status_codes, content_types_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			epID, projectID, host, method, template, canonical, now, now,
			string(statusJSON), string(ctJSON),
		)
	} else {
		db.Exec(`
			UPDATE endpoints SET last_seen = ?, request_count = request_count + 1
			WHERE id = ?`, now, epID)
	}

	db.Exec(`UPDATE requests SET endpoint_id = ? WHERE id = ?`, epID, reqID)

	extractParams(db, epID, reqID, queryString, headers, body)
}

func findEndpoint(db *sql.DB, projectID, host, method, template, path string) (string, error) {
	var epID string
	err := db.QueryRow(
		`SELECT id FROM endpoints WHERE project_id = ? AND host = ? AND method = ? AND path_template = ?`,
		projectID, host, method, template,
	).Scan(&epID)
	if err == nil {
		return epID, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}

	count := SegmentCount(template)
	rows, err := db.Query(
		`SELECT id, path_template FROM endpoints
		 WHERE project_id = ? AND host = ? AND method = ?
		   AND path_template LIKE '%{%}'`,
		projectID, host, method,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var bestID string
	bestPlaceholders := -1
	for rows.Next() {
		var cID, cTemplate string
		if err := rows.Scan(&cID, &cTemplate); err != nil {
			continue
		}
		if SegmentCount(cTemplate) != count || !TemplateFits(cTemplate, path) {
			continue
		}
		ph := strings.Count(cTemplate, "{")
		if ph > bestPlaceholders {
			bestID = cID
			bestPlaceholders = ph
		}
	}
	if bestID != "" {
		return bestID, nil
	}
	return "", sql.ErrNoRows
}

func extractParams(db *sql.DB, epID, reqID, queryString string, headers http.Header, body []byte) {
	for k, vals := range parseQuery(queryString) {
		for _, v := range vals {
			upsertParam(db, epID, reqID, k, "query", inferType(v), maskSensitive(k, v))
		}
	}

	for k, v := range parseCookies(headers.Get("Cookie")) {
		upsertParam(db, epID, reqID, k, "cookie", "string", maskSensitive(k, v))
	}

	if auth := headers.Get("Authorization"); auth != "" {
		upsertParam(db, epID, reqID, "Authorization", "header", "string", "[redacted]")
	}

	ct := headers.Get("Content-Type")
	switch {
	case strings.Contains(ct, "application/json"):
		extractJSONParams(db, epID, reqID, body)
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		for k, vals := range parseQuery(string(body)) {
			for _, v := range vals {
				upsertParam(db, epID, reqID, k, "form_body", inferType(v), maskSensitive(k, v))
			}
		}
	case strings.Contains(ct, "multipart/form-data"):
		extractMultipartParams(db, epID, reqID, ct, body)
	case strings.Contains(ct, "application/xml") || strings.Contains(ct, "text/xml"):
		extractXMLParams(db, epID, reqID, body)
	}
}

func extractMultipartParams(db *sql.DB, epID, reqID, contentType string, body []byte) {
	boundary := boundaryFromCT(contentType)
	if boundary == "" {
		return
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			return
		}
		name := part.FormName()
		filename := part.FileName()
		if filename != "" {

			upsertParam(db, epID, reqID, name, "multipart", "file", "[file]")
			continue
		}
		val, err := io.ReadAll(part)
		if err != nil {
			continue
		}
		if name != "" {
			upsertParam(db, epID, reqID, name, "multipart", inferType(string(val)), maskSensitive(name, string(val)))
		}
	}
}

func boundaryFromCT(contentType string) string {
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "boundary=") {
			return strings.Trim(strings.TrimPrefix(part, "boundary="), `"`)
		}
	}
	return ""
}

func extractXMLParams(db *sql.DB, epID, reqID string, body []byte) {
	text := string(body)
	idx := 0
	for {
		open := strings.Index(text[idx:], "<")
		if open == -1 {
			return
		}
		open += idx
		close := strings.Index(text[open:], ">")
		if close == -1 {
			return
		}
		close += open
		tag := strings.TrimSpace(text[open+1 : close])
		if strings.HasPrefix(tag, "/") || strings.HasPrefix(tag, "?") || strings.HasPrefix(tag, "!") {
			idx = close + 1
			continue
		}
		if sp := strings.IndexAny(tag, " \t\r\n"); sp != -1 {
			tag = tag[:sp]
		}
		endTag := "</" + tag + ">"
		end := strings.Index(text[close+1:], endTag)
		if end == -1 {
			idx = close + 1
			continue
		}
		end += close + 1
		val := strings.TrimSpace(text[close+1 : end])
		if val != "" && !strings.Contains(val, "<") {
			upsertParam(db, epID, reqID, tag, "xml_body", inferType(val), maskSensitive(tag, val))
		}
		idx = end + len(endTag)
	}
}

func upsertParam(db *sql.DB, epID, reqID, name, location, inferredType, exampleVal string) {
	var paramID string
	var examplesJSON string
	err := db.QueryRow(
		`SELECT id, example_values FROM parameters WHERE endpoint_id = ? AND name = ? AND location = ?`,
		epID, name, location,
	).Scan(&paramID, &examplesJSON)

	if err == sql.ErrNoRows {
		paramID = core.NewID("param")
		examples := []string{}
		if exampleVal != "" {
			examples = []string{exampleVal}
		}
		exJSON, _ := json.Marshal(examples)
		observedJSON, _ := json.Marshal([]string{reqID})
		db.Exec(`
			INSERT INTO parameters (id, endpoint_id, name, location, inferred_type, example_values, observed_in)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			paramID, epID, name, location, inferredType, string(exJSON), string(observedJSON),
		)
	} else if err == nil {
		var examples []string
		json.Unmarshal([]byte(examplesJSON), &examples)
		if len(examples) < 5 && exampleVal != "" && !contains(examples, exampleVal) {
			examples = append(examples, exampleVal)
			exJSON, _ := json.Marshal(examples)
			db.Exec(`UPDATE parameters SET example_values = ?, inferred_type = ? WHERE id = ?`,
				string(exJSON), inferredType, paramID)
		}
		var observedJSON string
		db.QueryRow(`SELECT observed_in FROM parameters WHERE id = ?`, paramID).Scan(&observedJSON)
		var observed []string
		json.Unmarshal([]byte(observedJSON), &observed)
		if !contains(observed, reqID) {
			observed = append(observed, reqID)
			if len(observed) > 10 {
				observed = observed[len(observed)-10:]
			}
			obsJSON, _ := json.Marshal(observed)
			db.Exec(`UPDATE parameters SET observed_in = ? WHERE id = ?`, string(obsJSON), paramID)
		}
	}
}

func extractJSONParams(db *sql.DB, epID, reqID string, body []byte) {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return
	}
	flattenJSON(db, epID, reqID, obj, "")
}

func flattenJSON(db *sql.DB, epID, reqID string, obj map[string]interface{}, prefix string) {
	for k, v := range obj {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		valStr := ""
		switch vt := v.(type) {
		case string:
			valStr = vt
		case float64:
			valStr = strconv.FormatFloat(vt, 'f', -1, 64)
		case bool:
			if vt {
				valStr = "true"
			} else {
				valStr = "false"
			}
		case map[string]interface{}:
			flattenJSON(db, epID, reqID, vt, key)
			continue
		}
		upsertParam(db, epID, reqID, key, "json_body", inferType(valStr), maskSensitive(key, valStr))
	}
}

func inferType(v string) string {
	if v == "true" || v == "false" {
		return "boolean"
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return "integer"
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return "number"
	}
	if _, err := time.Parse(time.RFC3339, v); err == nil {
		return "datetime"
	}
	return "string"
}

var sensitiveParamNames = []string{
	"password", "passwd", "pass", "secret", "token", "key", "apikey",
	"api_key", "auth", "authorization", "credential", "private",
}

func maskSensitive(name, value string) string {
	lower := strings.ToLower(name)
	for _, s := range sensitiveParamNames {
		if strings.Contains(lower, s) {
			return "[redacted]"
		}
	}
	return value
}

func UpdateEndpointResponse(db *sql.DB, reqID string, statusCode int, contentType string) {
	var epID string
	if err := db.QueryRow(`SELECT endpoint_id FROM requests WHERE id = ?`, reqID).Scan(&epID); err != nil || epID == "" {
		return
	}

	var codesJSON string
	if err := db.QueryRow(`SELECT observed_status_codes FROM endpoints WHERE id = ?`, epID).Scan(&codesJSON); err == nil {
		var codes []int
		json.Unmarshal([]byte(codesJSON), &codes)
		found := false
		for _, c := range codes {
			if c == statusCode {
				found = true
				break
			}
		}
		if !found {
			codes = append(codes, statusCode)
			j, _ := json.Marshal(codes)
			db.Exec(`UPDATE endpoints SET observed_status_codes = ? WHERE id = ?`, string(j), epID)
		}
	}

	if contentType != "" {
		var ctJSON string
		if err := db.QueryRow(`SELECT content_types_json FROM endpoints WHERE id = ?`, epID).Scan(&ctJSON); err == nil {
			var cts []string
			json.Unmarshal([]byte(ctJSON), &cts)
			if !contains(cts, contentType) {
				cts = append(cts, contentType)
				j, _ := json.Marshal(cts)
				db.Exec(`UPDATE endpoints SET content_types_json = ? WHERE id = ?`, string(j), epID)
			}
		}
	}

	if statusCode == 401 || statusCode == 403 {
		db.Exec(`UPDATE endpoints SET auth_required = 1 WHERE id = ?`, epID)
	}
}

func parseQuery(q string) map[string][]string {
	result := map[string][]string{}
	if q == "" {
		return result
	}
	parts := strings.Split(q, "&")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		k := kv[0]
		v := ""
		if len(kv) == 2 {
			v = kv[1]
		}
		result[k] = append(result[k], v)
	}
	return result
}

func parseCookies(cookieHeader string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

func contains(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}
