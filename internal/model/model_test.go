package model

import (
	"strings"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		s    Severity
		want int
	}{
		{SeverityInfo, 1},
		{SeverityLow, 2},
		{SeverityMedium, 3},
		{SeverityHigh, 4},
		{SeverityCritical, 5},
		{Severity(""), 0},
		{Severity("unknown"), 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.s), func(t *testing.T) {
			got := SeverityRank(tt.s)
			if got != tt.want {
				t.Errorf("SeverityRank(%q) = %d, want %d", tt.s, got, tt.want)
			}
		})
	}
}

func TestSortFindings(t *testing.T) {
	findings := []Finding{
		{Code: "TLS-001", Severity: SeverityLow},
		{Code: "CERT-001", Severity: SeverityCritical},
		{Code: "DNS-001", Severity: SeverityCritical},
		{Code: "HTTP-001", Severity: SeverityMedium},
	}
	SortFindings(findings)
	// Expect: critical first (CERT-001, DNS-001 by code), then medium, then low
	if findings[0].Severity != SeverityCritical || findings[1].Severity != SeverityCritical {
		t.Errorf("expected critical first, got %s then %s", findings[0].Severity, findings[1].Severity)
	}
	if findings[0].Code >= findings[1].Code {
		t.Errorf("expected codes ordered: got %s, %s", findings[0].Code, findings[1].Code)
	}
	if findings[2].Severity != SeverityMedium {
		t.Errorf("expected medium third, got %s", findings[2].Severity)
	}
	if findings[3].Severity != SeverityLow {
		t.Errorf("expected low fourth, got %s", findings[3].Severity)
	}
}

func TestSortFindings_Stable(t *testing.T) {
	findings := []Finding{
		{Code: "A", Severity: SeverityInfo},
		{Code: "B", Severity: SeverityInfo},
	}
	SortFindings(findings)
	if findings[0].Code != "A" || findings[1].Code != "B" {
		t.Errorf("stable sort: expected A then B, got %s then %s", findings[0].Code, findings[1].Code)
	}
}

func TestReport_RenderText(t *testing.T) {
	r := Report{
		URL:     "https://example.com",
		Host:    "example.com",
		Port:    "443",
		Overall: "pass",
		DNS:     DNSResult{LookupMS: 10},
		Findings: []Finding{},
	}
	out := r.RenderText()
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS in output")
	}
	if !strings.Contains(out, "https://example.com") {
		t.Error("expected URL in output")
	}
	if !strings.Contains(out, "Findings") {
		t.Error("expected Findings section")
	}
	if !strings.Contains(out, "none") {
		t.Error("expected 'none' for no findings")
	}
}

func TestReport_RenderText_WithFindings(t *testing.T) {
	r := Report{
		URL:     "https://example.com",
		Host:    "example.com",
		Port:    "443",
		Overall: "warn",
		DNS:     DNSResult{LookupMS: 5},
		Findings: []Finding{
			{Code: "HTTP-011", Severity: SeverityLow, Title: "HSTS header missing", Description: "Missing."},
		},
	}
	out := r.RenderText()
	if !strings.Contains(out, "WARN") {
		t.Error("expected WARN in output")
	}
	if !strings.Contains(out, "HTTP-011") {
		t.Error("expected finding code in output")
	}
	if !strings.Contains(out, "HSTS header missing") {
		t.Error("expected finding title in output")
	}
}
