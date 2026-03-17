package policy

import (
	"fmt"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
)

type Profile struct {
	Name                 string
	RequireHSTS          bool
	RequireCAA           bool
	RequireTLS13Or12     bool
	ForbidLegacyTLS      bool
	ForbidWeakCiphers    bool
	RequireModernHeaders bool
}

func ModernProfile() Profile {
	return Profile{
		Name: "modern", RequireHSTS: true, RequireCAA: false, RequireTLS13Or12: true,
		ForbidLegacyTLS: true, ForbidWeakCiphers: true, RequireModernHeaders: true,
	}
}

func StrictProfile() Profile {
	return Profile{
		Name: "strict", RequireHSTS: true, RequireCAA: true, RequireTLS13Or12: true,
		ForbidLegacyTLS: true, ForbidWeakCiphers: true, RequireModernHeaders: true,
	}
}

func ProfileByName(name string) Profile {
	if name == "strict" { return StrictProfile() }
	return ModernProfile()
}

func ApplyProfile(report *model.Report, profile Profile) []model.Finding {
	logx.Debug("ApplyProfile", "profile", profile.Name, "host", report.Host)
	var findings []model.Finding
	if profile.RequireCAA && len(report.DNS.CAARecords) == 0 {
		findings = append(findings, model.Finding{
			Code: "POL-001", Severity: model.SeverityLow, Title: "Strict profile: no CAA DNS records",
			Description: "Profile «strict» expects CAA records so only approved CAs can issue certs for this zone.",
			Evidence:    fmt.Sprintf("Host %q — profile=%s — CAA lookup returned no records.", report.Host, profile.Name),
			Remediation: "Add CAA at DNS (e.g. 0 issue \"letsencrypt.org\") for the hostname and parent zone as needed.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
		})
	}
	// Header gaps are already one finding per header (HTTP-015); no duplicate POL-002.
	return findings
}
