package policy

import (
	"sslcheck/internal/model"
	"testing"
)

func TestConsistencyFindings_DualStackIPv4IPv6LeafMismatch(t *testing.T) {
	sameLeaf := &model.CertificateSummary{
		SerialNumber: "abc", SubjectCommonName: "example.com", NotAfter: "2030-01-01",
	}
	diffLeaf := &model.CertificateSummary{
		SerialNumber: "xyz", SubjectCommonName: "example.com", NotAfter: "2030-01-01",
	}
	t.Run("mismatch", func(t *testing.T) {
		eps := []model.EndpointResult{
			{IP: "192.0.2.1", TLSHandshakeOK: true, CertSummary: sameLeaf},
			{IP: "2001:db8::1", TLSHandshakeOK: true, CertSummary: diffLeaf},
		}
		got := ConsistencyFindings(eps)
		var seen004, seen003 bool
		for _, f := range got {
			switch f.Code {
			case "EDGE-004":
				seen004 = true
			case "EDGE-003":
				seen003 = true
			}
		}
		if !seen004 {
			t.Errorf("expected EDGE-004 in %#v", got)
		}
		if seen003 {
			t.Errorf("did not expect EDGE-003 when only IPv4 vs IPv6 singleton mismatch (got %#v)", got)
		}
	})
	t.Run("multi cert ipv4 still EDGE-003", func(t *testing.T) {
		a := &model.CertificateSummary{SerialNumber: "a", SubjectCommonName: "x", NotAfter: "2030-01-01"}
		b := &model.CertificateSummary{SerialNumber: "b", SubjectCommonName: "x", NotAfter: "2030-01-01"}
		eps := []model.EndpointResult{
			{IP: "192.0.2.1", TLSHandshakeOK: true, CertSummary: a},
			{IP: "192.0.2.2", TLSHandshakeOK: true, CertSummary: b},
			{IP: "2001:db8::1", TLSHandshakeOK: true, CertSummary: a},
		}
		var seen003, seen004 bool
		for _, f := range ConsistencyFindings(eps) {
			switch f.Code {
			case "EDGE-003":
				seen003 = true
			case "EDGE-004":
				seen004 = true
			}
		}
		if !seen003 {
			t.Error("expected EDGE-003 when multiple IPv4 leaf certs")
		}
		if !seen004 {
			t.Error("expected EDGE-004 when IPv4 leaf set differs from IPv6")
		}
	})
	t.Run("same cert both families", func(t *testing.T) {
		eps := []model.EndpointResult{
			{IP: "192.0.2.1", TLSHandshakeOK: true, CertSummary: sameLeaf},
			{IP: "2001:db8::1", TLSHandshakeOK: true, CertSummary: sameLeaf},
		}
		for _, f := range ConsistencyFindings(eps) {
			if f.Code == "EDGE-004" {
				t.Errorf("unexpected EDGE-004")
			}
		}
	})
	t.Run("ipv6 only no EDGE-004", func(t *testing.T) {
		eps := []model.EndpointResult{
			{IP: "2001:db8::1", TLSHandshakeOK: true, CertSummary: sameLeaf},
			{IP: "2001:db8::2", TLSHandshakeOK: true, CertSummary: diffLeaf},
		}
		for _, f := range ConsistencyFindings(eps) {
			if f.Code == "EDGE-004" {
				t.Errorf("unexpected EDGE-004 for single-family endpoints")
			}
		}
	})
}

func TestDeriveOverall(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		want     string
	}{
		{"empty", nil, "pass"},
		{"info only", []model.Finding{{Severity: model.SeverityInfo}}, "pass"},
		{"low", []model.Finding{{Severity: model.SeverityLow}}, "warn"},
		{"medium", []model.Finding{{Severity: model.SeverityMedium}}, "warn"},
		{"high", []model.Finding{{Severity: model.SeverityHigh}}, "fail"},
		{"critical", []model.Finding{{Severity: model.SeverityCritical}}, "fail"},
		{"worst wins", []model.Finding{
			{Severity: model.SeverityInfo},
			{Severity: model.SeverityCritical},
		}, "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveOverall(tt.findings)
			if got != tt.want {
				t.Errorf("DeriveOverall() = %q, want %q", got, tt.want)
			}
		})
	}
}
