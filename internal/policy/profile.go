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
	RequireCAASatisfied  bool
	RequireMustStapleOK  bool
	RequireCTLikelyOK    bool
	RequireCRLChecked    bool
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
		RequireCAASatisfied: true, RequireMustStapleOK: true, RequireCTLikelyOK: true, RequireCRLChecked: true,
	}
}

func FastProfile() Profile {
	return Profile{
		Name: "fast", RequireHSTS: false, RequireCAA: false, RequireTLS13Or12: true,
		ForbidLegacyTLS: true, ForbidWeakCiphers: true, RequireModernHeaders: false,
	}
}

func ProfileByName(name string) Profile {
	switch name {
	case "strict":
		return StrictProfile()
	case "fast":
		return FastProfile()
	default:
		return ModernProfile()
	}
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
	if profile.RequireCAASatisfied && report.DNS.CAASatisfiesScan == "policy_mismatch" {
		findings = append(findings, model.Finding{
			Code: "POL-003", Severity: model.SeverityHigh, Title: "Strict profile: CAA does not authorize issuer",
			Description: "Profile requires CAA to allow the observed certificate issuer.",
			Evidence: fmt.Sprintf("caa_satisfies_scan=%q", report.DNS.CAASatisfiesScan),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
		})
	}
	for _, ep := range report.Endpoints {
		if !ep.TLSHandshakeOK {
			continue
		}
		if profile.RequireMustStapleOK && ep.Revocation != nil && ep.Revocation.MustStapleRequired {
			if !ep.Revocation.StapledOCSP || ep.Revocation.StapledOCSPStatus != "good" {
				findings = append(findings, model.Finding{
					Code: "POL-004", Severity: model.SeverityCritical, Title: "Strict profile: Must-Staple not satisfied",
					Description: "Certificate requires OCSP Must-Staple but stapling is missing or not good.",
					Evidence: fmt.Sprintf("IP %s revocation_status=%q", ep.IP, ep.Revocation.OverallRevocationStatus),
					ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc7633",
				})
			}
		}
		if profile.RequireCTLikelyOK && ep.CertificateTransparency != nil && ep.CertificateTransparency.CTCompliance == "failed" {
			findings = append(findings, model.Finding{
				Code: "POL-005", Severity: model.SeverityMedium, Title: "Strict profile: no CT/SCT evidence",
				Description: "Profile expects certificate transparency signals (embedded SCT or handshake SCTs).",
				Evidence: fmt.Sprintf("IP %s sct_count=%d", ep.IP, ep.CertificateTransparency.SCTCount),
				ReferenceURL: "https://certificate.transparency.dev/",
			})
		}
		if profile.RequireCRLChecked && ep.Revocation != nil && ep.Revocation.CRLStatus == "no_urls" {
			findings = append(findings, model.Finding{
				Code: "POL-006", Severity: model.SeverityLow, Title: "Strict profile: no CRL distribution points",
				Description: "Profile expects CRL URLs on the leaf for offline revocation checking.",
				Evidence: fmt.Sprintf("IP %s", ep.IP),
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3",
			})
		}
		break
	}
	return findings
}
