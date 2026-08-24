package cmd

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/msdbg/AgentBurp/internal/differ"
	"github.com/msdbg/AgentBurp/internal/models"
)

func resolveExchange(db *sql.DB, id string) (*models.Request, *models.Response, error) {
	prefix, err := corePrefix(id)
	if err != nil {
		return nil, nil, err
	}
	switch prefix {
	case "req":
		req, err := fetchRequest(db, id, 0, false)
		if err != nil {
			return nil, nil, err
		}
		resp, _ := fetchResponse(db, id, 0, false)
		return req, resp, nil
	case "rreq":
		row := db.QueryRow(`
			SELECT method, url, headers_json, COALESCE(body_blob,'') FROM repeater_requests WHERE id = ?`, id)
		var method, rawURL, headersJSON string
		var body []byte
		if err := row.Scan(&method, &rawURL, &headersJSON, &body); err != nil {
			return nil, nil, fmt.Errorf("repeater request %q not found", id)
		}
		req := &models.Request{ID: id, Method: method, URL: rawURL, Body: body}
		json.Unmarshal([]byte(headersJSON), &req.Headers)
		req.BodySize = len(body)
		req.BodyHash = hashHex(body)

		var reqID string
		err = db.QueryRow(`
			SELECT id FROM requests WHERE note = ? ORDER BY created_at DESC LIMIT 1`, id).Scan(&reqID)
		if err == nil && reqID != "" {
			resp, rerr := fetchResponse(db, reqID, 0, false)
			if rerr == nil {
				return req, resp, nil
			}
		}
		return req, nil, nil
	default:
		return nil, nil, fmt.Errorf("unsupported object type %q — use req_* or rreq_* IDs", prefix)
	}
}

func diffObjects(db *sql.DB, aID, bID, kind string) (*differ.DiffResult, error) {
	reqA, respA, err := resolveExchange(db, aID)
	if err != nil {
		return nil, err
	}
	reqB, respB, err := resolveExchange(db, bID)
	if err != nil {
		return nil, err
	}

	switch kind {
	case "request":
		if reqA == nil || reqB == nil {
			return nil, fmt.Errorf("cannot diff requests: one of the objects has no request data")
		}
		return differ.DiffRequests(reqA, reqB), nil
	case "response":
		if respA == nil || respB == nil {
			return nil, fmt.Errorf("cannot diff responses: one of the objects has no response data (send it first)")
		}
		return differ.DiffResponses(respA, respB), nil
	default:
		return nil, fmt.Errorf("unknown diff kind %q", kind)
	}
}

func printDiffHuman(d *differ.DiffResult) {
	status := "DIFFERENT"
	if d.Same {
		status = "IDENTICAL"
	}
	fmt.Printf("━━━ %s DIFF ━━━ %s\n", d.Kind, status)

	if d.Method != nil && d.Method.Changed {
		fmt.Printf("Method: %s → %s\n", d.Method.Before, d.Method.After)
	}
	if d.URL != nil && d.URL.Changed {
		fmt.Printf("URL:    %s\n       → %s\n", d.URL.Before, d.URL.After)
	}
	if d.Status != nil && d.Status.Changed {
		fmt.Printf("Status: %s → %s\n", d.Status.Before, d.Status.After)
	}
	if d.Reason != nil && d.Reason.Changed {
		fmt.Printf("Reason: %s → %s\n", d.Reason.Before, d.Reason.After)
	}

	if d.Headers.Changed {
		fmt.Printf("\nHeaders:\n")
		for _, h := range d.Headers.Added {
			fmt.Printf("  + %s: %s\n", h.Name, h.After)
		}
		for _, h := range d.Headers.Removed {
			fmt.Printf("  - %s: %s\n", h.Name, h.Before)
		}
		for _, h := range d.Headers.Modified {
			fmt.Printf("  ~ %s: %s → %s\n", h.Name, h.Before, h.After)
		}
	}

	if d.Body != nil && d.Body.Changed {
		fmt.Printf("\nBody: (%s → %s bytes)\n", humanBytes(d.Body.BeforeSize), humanBytes(d.Body.AfterSize))
		for _, l := range d.Body.Lines {
			switch l.Type {
			case "add":
				fmt.Printf("  + %s\n", l.Line)
			case "del":
				fmt.Printf("  - %s\n", l.Line)
			}
		}
	}
	if d.Same {
		fmt.Println("\nNo differences found.")
	}
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func corePrefix(id string) (string, error) {
	for i := 0; i < len(id); i++ {
		if id[i] == '_' {
			return id[:i], nil
		}
	}
	return "", fmt.Errorf("invalid id %q — expected prefix_nanoid format", id)
}
