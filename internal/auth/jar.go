package auth

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/msdbg/AgentBurp/internal/models"
)

type CaptureResult struct {
	SessionID string            `json:"session_id"`
	RequestID string            `json:"request_id"`
	Cookies   int               `json:"cookies_captured"`
	Headers   []string          `json:"headers_captured"`
	Tokens    map[string]string `json:"tokens_captured"`
}

var tokenKeysInResponse = []string{
	"access_token", "id_token", "refresh_token", "token",
	"api_key", "apikey", "session_id", "csrf_token", "jwt",
}
var tokenMetaKeys = []string{
	"token_type", "token_type_hint", "expires_in", "expires_at",
	"scope", "refresh_expires_in", "id_token_expires_in", "not_before_policy",
	"auth_time", "acr", "amr", "sub", "jti", "sid",
}

func isTokenMeta(k string) bool {
	lower := strings.ToLower(k)
	for _, mk := range tokenMetaKeys {
		if strings.Contains(lower, mk) {
			return true
		}
	}
	return false
}

func CaptureFromTraffic(db *sql.DB, projectID, sessID, reqID string) (*CaptureResult, error) {
	store := &SessionStore{db: db, projectID: projectID}

	sess, err := store.Get(sessID)
	if err != nil {
		return nil, err
	}

	var reqHeadersJSON string
	err = db.QueryRow(`SELECT headers_json FROM requests WHERE id = ?`, reqID).Scan(&reqHeadersJSON)
	if err != nil {
		return nil, err
	}
	var reqHeaders []models.Header
	json.Unmarshal([]byte(reqHeadersJSON), &reqHeaders)

	var respHeadersJSON, bodyJSON string
	err = db.QueryRow(`
		SELECT headers_json, COALESCE(CAST(body_blob AS TEXT),'') FROM responses
		WHERE request_id = ? ORDER BY created_at DESC LIMIT 1`, reqID,
	).Scan(&respHeadersJSON, &bodyJSON)
	if err != nil {
		return nil, err
	}
	var respHeaders []models.Header
	json.Unmarshal([]byte(respHeadersJSON), &respHeaders)

	result := &CaptureResult{
		SessionID: sessID,
		RequestID: reqID,
		Tokens:    map[string]string{},
	}

	hdr := http.Header{}
	for _, h := range respHeaders {
		hdr.Add(h.Name, h.Value)
	}
	if cookies := hdr.Values("Set-Cookie"); len(cookies) > 0 {
		result.Cookies = store.SetCookies(sess, cookies)
	}

	tokens := map[string]string{}
	var capturedHeaders []string
	for _, h := range reqHeaders {
		lower := strings.ToLower(h.Name)
		if lower == "authorization" || strings.Contains(lower, "token") || strings.Contains(lower, "api-key") ||
			lower == "x-api-key" || lower == "x-csrf-token" {
			tokens[h.Name] = h.Value
			if lower == "authorization" {
				tokens["Authorization"] = h.Value
			}
			capturedHeaders = append(capturedHeaders, h.Name)
		}
	}
	result.Headers = capturedHeaders

	if len(bodyJSON) > 0 && strings.HasPrefix(strings.TrimSpace(bodyJSON), "{") {
		var obj map[string]interface{}
		if json.Unmarshal([]byte(bodyJSON), &obj) == nil {
			collectTokenValues(obj, "", tokens)
		}
	}
	for k, v := range tokens {
		result.Tokens[k] = v
	}
	store.SetTokens(sess, tokens)

	if err := store.Save(sess); err != nil {
		return nil, err
	}
	return result, nil
}

func collectTokenValues(obj map[string]interface{}, prefix string, out map[string]string) {
	for k, v := range obj {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		lower := strings.ToLower(k)
		if sub, ok := v.(map[string]interface{}); ok {
			collectTokenValues(sub, key, out)
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			if isTokenMeta(k) {
				continue
			}
			for _, tk := range tokenKeysInResponse {
				if strings.Contains(lower, tk) {
					if _, exists := out[k]; !exists {
						out[k] = s
					}
					if tk == "access_token" || tk == "id_token" || tk == "token" {
						if _, exists := out["Authorization"]; !exists {
							out["Authorization"] = "Bearer " + s
						}
					}
					break
				}
			}
		}
	}
}
