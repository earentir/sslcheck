package policy

import (
	"reflect"
	"testing"

	"sslcheck/internal/model"
)

func TestProfileByName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Profile
	}{
		{"modern", "modern", ModernProfile()},
		{"strict", "strict", StrictProfile()},
		{"unknown defaults to modern", "invalid", ModernProfile()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProfileByName(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProfileByName(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestProfileByName_StrictVsModern(t *testing.T) {
	strict := ProfileByName("strict")
	modern := ProfileByName("modern")
	if strict.Name != "strict" || modern.Name != "modern" {
		t.Errorf("names: strict=%q modern=%q", strict.Name, modern.Name)
	}
	if !strict.RequireCAA || modern.RequireCAA {
		t.Error("strict should require CAA, modern should not")
	}
}

func TestApplyProfile_RequireCAA(t *testing.T) {
	report := &model.Report{Host: "example.com", DNS: model.DNSResult{CAARecords: nil}}
	findings := ApplyProfile(report, StrictProfile())
	var hasPOL001 bool
	for _, f := range findings {
		if f.Code == "POL-001" {
			hasPOL001 = true
			break
		}
	}
	if !hasPOL001 {
		t.Error("expected POL-001 when strict profile and no CAA")
	}
}

func TestApplyProfile_RequireCAA_WhenPresent(t *testing.T) {
	report := &model.Report{DNS: model.DNSResult{CAARecords: []model.CAARecord{{Tag: "issue", Value: "ca.example.com"}}}}
	findings := ApplyProfile(report, StrictProfile())
	for _, f := range findings {
		if f.Code == "POL-001" {
			t.Error("should not have POL-001 when CAA records present")
		}
	}
}

func TestApplyProfile_NoDuplicatePOL002ForHeaders(t *testing.T) {
	report := &model.Report{
		HTTP: model.HTTPResult{
			HeaderIssues: []model.HeaderIssue{{Header: "Content-Security-Policy", Problem: "missing"}},
		},
	}
	findings := ApplyProfile(report, ModernProfile())
	for _, f := range findings {
		if f.Code == "POL-002" {
			t.Error("POL-002 removed — use HTTP-015 per header instead")
		}
	}
}
