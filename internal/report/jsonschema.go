package report

import "encoding/json"

type Field struct {
	Type        string           `json:"type,omitempty"`
	Description string           `json:"description,omitempty"`
	Properties  map[string]Field `json:"properties,omitempty"`
	Items       *Field           `json:"items,omitempty"`
	Required    []string         `json:"required,omitempty"`
	Enum        []string         `json:"enum,omitempty"`
}

func JSONSchema() ([]byte, error) {
	root := Field{
		Type: "object",
		Description: "sslcheck report schema",
		Properties: map[string]Field{
			"url": {Type: "string"},
			"host": {Type: "string"},
			"port": {Type: "string"},
			"overall": {Type: "string", Enum: []string{"pass", "warn", "fail"}},
			"started_at": {Type: "string"},
			"finished_at": {Type: "string"},
			"duration_ms": {Type: "integer"},
			"phase_timings": {
				Type: "array",
				Items: &Field{
					Type: "object",
					Properties: map[string]Field{
						"name":        {Type: "string"},
						"duration_ms": {Type: "integer"},
					},
				},
			},
			"redirect_chain": {Type: "array", Items: &Field{Type: "string"}},
			"findings": {
				Type: "array",
				Items: &Field{
					Type: "object",
					Properties: map[string]Field{
						"code": {Type: "string"},
						"severity": {Type: "string", Enum: []string{"info", "low", "medium", "high", "critical"}},
						"title": {Type: "string"},
						"description": {Type: "string"},
						"evidence": {Type: "string"},
						"remediation":   {Type: "string"},
						"reference_url": {Type: "string", Description: "optional documentation link"},
					},
				},
			},
		},
		Required: []string{"url", "host", "port", "overall", "findings"},
	}
	return json.MarshalIndent(root, "", "  ")
}
