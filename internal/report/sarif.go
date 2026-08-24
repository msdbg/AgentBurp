package report

import (
	"encoding/json"
	"fmt"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription sarifText          `json:"shortDescription"`
	FullDescription  sarifText          `json:"fullDescription,omitempty"`
	DefaultConfig    sarifConfiguration `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any     `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func (r *Report) SARIF() ([]byte, error) {
	checkIDs := r.CheckLabels()
	checkIndex := make(map[string]int, len(checkIDs))
	for i, c := range checkIDs {
		checkIndex[c] = i
	}

	severityByCheck := map[string]string{}
	for i := range r.Findings {
		f := &r.Findings[i]
		cur, ok := severityByCheck[f.CheckID]
		if !ok || severityRank[f.Severity] < severityRank[cur] {
			severityByCheck[f.CheckID] = f.Severity
		}
	}

	rules := make([]sarifRule, 0, len(checkIDs))
	for _, c := range checkIDs {
		rule := sarifRule{
			ID:               c,
			ShortDescription: sarifText{Text: c},
			DefaultConfig:    sarifConfiguration{Level: sarifLevel(severityByCheck[c])},
			Properties:       map[string]any{"tags": []string{"security"}},
		}
		rules = append(rules, rule)
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		res := sarifResult{
			RuleID:    f.CheckID,
			RuleIndex: checkIndex[f.CheckID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: fmt.Sprintf("[%s] %s", f.Severity, f.Title)},
		}
		if f.RequestURL != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.RequestURL},
					Region:           &sarifRegion{StartLine: 1},
				},
			}}
		}
		res.PartialFingerprints = map[string]string{
			"agentburpFindingID": f.ID,
		}
		results = append(results, res)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "AgentBurp",
				Version:        "0.1.0",
				InformationURI: "https://github.com/msdbg/AgentBurp",
				Rules:          rules,
			}},
			Results: results,
			Properties: map[string]any{
				"project_id":   r.Project.ID,
				"generated_at": r.GeneratedAt,
			},
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}
