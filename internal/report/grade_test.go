package report

import (
	"testing"

	"sslcheck/internal/model"
)

func TestGrade(t *testing.T) {
	tests := []struct {
		name string
		rep  model.Report
		want string
	}{
		{"pass clean", model.Report{Overall: "pass", Findings: nil}, "A+"},
		{"pass with info", model.Report{Overall: "pass", Findings: []model.Finding{{Severity: model.SeverityInfo}}}, "A"},
		{"warn medium", model.Report{Overall: "warn", Findings: []model.Finding{{Severity: model.SeverityMedium}}}, "C"},
		{"fail critical", model.Report{Overall: "fail", Findings: []model.Finding{{Severity: model.SeverityCritical}}}, "F"},
		{"fail high only", model.Report{Overall: "fail", Findings: []model.Finding{{Severity: model.SeverityHigh}}}, "D"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Grade(&tt.rep); got != tt.want {
				t.Fatalf("Grade()=%q want %q", got, tt.want)
			}
		})
	}
}
