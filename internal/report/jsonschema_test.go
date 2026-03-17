package report

import (
	"encoding/json"
	"testing"
)

func TestJSONSchema_Marshal(t *testing.T) {
	b, err := JSONSchema()
	if err != nil {
		t.Fatalf("JSONSchema() error = %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if m["type"] != "object" {
		t.Errorf("schema type = %v, want object", m["type"])
	}
	props, ok := m["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("schema.properties missing or wrong type")
	}
	for _, key := range []string{"url", "host", "port", "overall", "findings"} {
		if _, ok := props[key]; !ok {
			t.Errorf("schema.properties missing %q", key)
		}
	}
	req, ok := m["required"].([]interface{})
	if !ok || len(req) == 0 {
		t.Error("schema.required missing or empty")
	}
}
