package report

import "testing"

func TestAllCodes_ExpectedKeys(t *testing.T) {
	expected := []string{
		"CERT-001", "CERT-011", "CERT-012", "DNS-001", "EDGE-001", "EDGE-004",
		"HTTP-001", "NET-001", "NET-002", "POL-001", "TLS-001",
	}
	for _, code := range expected {
		if _, ok := AllCodes[code]; !ok {
			t.Errorf("AllCodes missing expected code %q", code)
		}
	}
}

func TestAllCodes_NoEmptyValue(t *testing.T) {
	for code, desc := range AllCodes {
		if desc == "" {
			t.Errorf("AllCodes[%q] is empty", code)
		}
	}
}
