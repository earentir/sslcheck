package policy

import (
	"sslcheck/internal/model"
	"testing"
)

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
