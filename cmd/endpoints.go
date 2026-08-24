package cmd

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
	"github.com/msdbg/AgentBurp/internal/output"
	"github.com/spf13/cobra"
)

func newEndpointsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoints",
		Short: "Browse the structured endpoint map",
		Long: `The endpoint map is AgentBurp's key differentiator over raw traffic.

Raw requests to /api/users/1, /api/users/2, /api/users/3 are normalized
into a single endpoint: GET /api/users/{id}

This gives AI agents a structured, machine-readable application map
instead of thousands of raw request entries.`,
	}
	cmd.AddCommand(
		endpointsListCmd(),
		endpointsShowCmd(),
		endpointsParamsCmd(),
		endpointsRequestsCmd(),
	)
	return cmd
}

func endpointsListCmd() *cobra.Command {
	var (
		filterHost   string
		filterMethod string
		filterPath   string
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all discovered endpoints",
		Example: `  agentburp endpoints list --json
  agentburp endpoints list --host api.example.com
  agentburp endpoints list --method POST
  agentburp endpoints list --path /api/users`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()
			proj, err := core.NewProjectStore(db).Get(projectName)
			if err != nil {
				return err
			}

			query := `
				SELECT id, project_id, host, method, path_template, canonical_path,
				       first_seen, last_seen, auth_required, request_count,
				       observed_status_codes, content_types_json
				FROM endpoints WHERE project_id = ?`
			args2 := []interface{}{proj.ID}
			if filterHost != "" {
				query += " AND host = ?"
				args2 = append(args2, filterHost)
			}
			if filterMethod != "" {
				query += " AND UPPER(method) = UPPER(?)"
				args2 = append(args2, filterMethod)
			}
			if filterPath != "" {
				query += " AND (path_template LIKE ? OR canonical_path LIKE ?)"
				args2 = append(args2, "%"+filterPath+"%", "%"+filterPath+"%")
			}
			query += " ORDER BY host, method, path_template"

			rows, err := db.Conn().Query(query, args2...)
			if err != nil {
				return err
			}
			defer rows.Close()

			endpoints := make([]models.Endpoint, 0)
			for rows.Next() {
				var ep models.Endpoint
				var statusJSON, ctJSON string
				var authInt int
				if err := rows.Scan(
					&ep.ID, &ep.ProjectID, &ep.Host, &ep.Method,
					&ep.PathTemplate, &ep.CanonicalPath,
					&ep.FirstSeen, &ep.LastSeen, &authInt,
					&ep.RequestCount, &statusJSON, &ctJSON,
				); err != nil {
					return err
				}
				ep.AuthRequired = authInt == 1
				json.Unmarshal([]byte(statusJSON), &ep.ObservedStatusCodes)
				json.Unmarshal([]byte(ctJSON), &ep.ContentTypes)
				endpoints = append(endpoints, ep)
			}

			output.PrintAuto(endpoints, func() {
				if len(endpoints) == 0 {
					fmt.Println("No endpoints discovered yet.")
					fmt.Println("Traffic through the proxy builds the endpoint map automatically.")
					return
				}
				headers := []string{"ID", "METHOD", "HOST", "PATH TEMPLATE", "REQUESTS", "STATUS CODES"}
				var tableRows [][]string
				for _, ep := range endpoints {
					codes := fmt.Sprintf("%v", ep.ObservedStatusCodes)
					tableRows = append(tableRows, []string{
						core.ShortID(ep.ID), ep.Method, ep.Host, ep.PathTemplate,
						fmt.Sprintf("%d", ep.RequestCount), codes,
					})
				}
				output.PrintTable(headers, tableRows)
				fmt.Printf("\n%d endpoints\n", len(endpoints))
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&filterHost, "host", "", "filter by host")
	cmd.Flags().StringVar(&filterMethod, "method", "", "filter by HTTP method")
	cmd.Flags().StringVar(&filterPath, "path", "", "filter by path (partial match)")
	return cmd
}

func endpointsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <ep_id>",
		Short: "Show full endpoint details including parameters",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			ep, err := fetchEndpoint(db.Conn(), args[0])
			if err != nil {
				return err
			}

			// Fetch parameters
			params, err := fetchParams(db.Conn(), ep.ID)
			if err != nil {
				return err
			}
			ep.Parameters = params

			output.PrintAuto(ep, func() {
				fmt.Printf("━━━ ENDPOINT ━━━ %s\n", ep.ID)
				fmt.Printf("  %s %s%s\n", ep.Method, ep.Host, ep.PathTemplate)
				fmt.Printf("  Requests:  %d\n", ep.RequestCount)
				fmt.Printf("  First seen: %s\n", ep.FirstSeen)
				fmt.Printf("  Last seen:  %s\n", ep.LastSeen)
				fmt.Printf("  Status codes: %v\n", ep.ObservedStatusCodes)
				if ep.AuthRequired {
					fmt.Printf("  Auth required: yes\n")
				}
				fmt.Printf("\nParameters (%d):\n", len(params))
				for _, p := range params {
					fmt.Printf("  [%s] %s (%s) — examples: %v\n",
						p.Location, p.Name, p.InferredType, p.ExampleValues)
				}
			})
			return nil
		},
	}
}

func endpointsParamsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "params <ep_id>",
		Short:   "List parameters observed at an endpoint",
		Args:    cobra.ExactArgs(1),
		Example: `  agentburp endpoints params ep_abc123 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			params, err := fetchParams(db.Conn(), args[0])
			if err != nil {
				return err
			}

			output.PrintAuto(params, func() {
				if len(params) == 0 {
					fmt.Println("No parameters observed yet.")
					return
				}
				headers := []string{"ID", "NAME", "LOCATION", "TYPE", "EXAMPLE VALUES"}
				var rows [][]string
				for _, p := range params {
					examples := fmt.Sprintf("%v", p.ExampleValues)
					rows = append(rows, []string{
						core.ShortID(p.ID), p.Name, p.Location, p.InferredType, examples,
					})
				}
				output.PrintTable(headers, rows)
			})
			return nil
		},
	}
}

func endpointsRequestsCmd() *cobra.Command {
	var limit int
	return &cobra.Command{
		Use:   "requests <ep_id>",
		Short: "List all requests to an endpoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := requireProject()
			db, err := openProjectDB(projectName)
			if err != nil {
				return err
			}
			defer db.Close()

			rows, err := db.Conn().Query(`
				SELECT r.id, r.method, r.url, COALESCE(rsp.status_code,0),
				       COALESCE(rsp.time_ms,0), r.created_at
				FROM requests r
				LEFT JOIN responses rsp ON rsp.request_id = r.id
				WHERE r.endpoint_id = ?
				ORDER BY r.created_at DESC LIMIT ?`, args[0], limit)
			if err != nil {
				return err
			}
			defer rows.Close()

			var entries []models.HistoryEntry
			for rows.Next() {
				var e models.HistoryEntry
				rows.Scan(&e.RequestID, &e.Method, &e.URL, &e.StatusCode, &e.TimeMs, &e.CreatedAt)
				entries = append(entries, e)
			}

			output.PrintAuto(entries, func() {
				fmt.Printf("%d requests to endpoint %s\n\n", len(entries), args[0])
				for _, e := range entries {
					fmt.Printf("  %s  %s → %d (%dms)\n",
						core.ShortID(e.RequestID), e.URL, e.StatusCode, e.TimeMs)
				}
			})
			return nil
		},
	}
}

func fetchEndpoint(db *sql.DB, epID string) (*models.Endpoint, error) {
	row := db.QueryRow(`
		SELECT id, project_id, host, method, path_template, canonical_path,
		       first_seen, last_seen, auth_required, request_count,
		       observed_status_codes, content_types_json
		FROM endpoints WHERE id = ?`, epID)
	var ep models.Endpoint
	var statusJSON, ctJSON string
	var authInt int
	if err := row.Scan(
		&ep.ID, &ep.ProjectID, &ep.Host, &ep.Method,
		&ep.PathTemplate, &ep.CanonicalPath,
		&ep.FirstSeen, &ep.LastSeen, &authInt,
		&ep.RequestCount, &statusJSON, &ctJSON,
	); err != nil {
		return nil, fmt.Errorf("endpoint %q not found", epID)
	}
	ep.AuthRequired = authInt == 1
	json.Unmarshal([]byte(statusJSON), &ep.ObservedStatusCodes)
	json.Unmarshal([]byte(ctJSON), &ep.ContentTypes)
	return &ep, nil
}

func fetchParams(db *sql.DB, epID string) ([]models.Parameter, error) {
	rows, err := db.Query(`
		SELECT id, endpoint_id, name, location, inferred_type, example_values, observed_in
		FROM parameters WHERE endpoint_id = ? ORDER BY location, name`, epID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var params []models.Parameter
	for rows.Next() {
		var p models.Parameter
		var exJSON, obsJSON string
		if err := rows.Scan(&p.ID, &p.EndpointID, &p.Name, &p.Location,
			&p.InferredType, &exJSON, &obsJSON); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(exJSON), &p.ExampleValues)
		json.Unmarshal([]byte(obsJSON), &p.ObservedIn)
		params = append(params, p)
	}
	return params, rows.Err()
}
