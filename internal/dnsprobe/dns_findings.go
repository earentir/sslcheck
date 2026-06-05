package dnsprobe

import (
	"fmt"
	"strings"

	"sslcheck/internal/model"
)

// DNSFindings builds DNS-phase findings from a collect result (no network I/O).
func DNSFindings(host string, result model.DNSResult, lookupErr error) []model.Finding {
	var findings []model.Finding
	if lookupErr != nil {
		findings = append(findings, model.Finding{
			Code: "DNS-001", Severity: model.SeverityCritical, Title: "DNS resolution failed",
			Description: fmt.Sprintf("Resolver could not resolve %q — no A/AAAA answers usable by the scanner.", host),
			Evidence:    lookupErr.Error(),
			Remediation: "Create A/AAAA records at your DNS provider; confirm propagation with dig/nslookup from another network.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Learn_web_development/Howto/Web_mechanics/What_is_a_domain_name",
		})
		return findings
	}
	if len(result.IPs) == 0 {
		findings = append(findings, model.Finding{
			Code: "DNS-002", Severity: model.SeverityCritical, Title: "No A/AAAA records for " + host,
			Description: "Lookup succeeded but produced no IPv4 or IPv6 addresses for this name.",
			Evidence:    fmt.Sprintf("Host %q returned zero IPs after lookup.", host),
			Remediation: "Add at least one A (IPv4) or AAAA (IPv6) record pointing to your origin.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Learn_web_development/Howto/Web_mechanics/What_is_a_domain_name",
		})
	} else if len(result.IPs) > 1 {
		findings = append(findings, model.Finding{
			Code: "DNS-003", Severity: model.SeverityInfo, Title: fmt.Sprintf("Multiple IPs for %s", host),
			Description: "Several addresses are published; the scanner will probe each and compare TLS behavior.",
			Evidence:    strings.Join(result.IPs, ", "),
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/Load_balancer",
		})
	}
	if len(result.CAARecords) == 0 {
		findings = append(findings, model.Finding{
			Code: "DNS-010", Severity: model.SeverityInfo, Title: "No CAA records for " + host,
			Description: "CAA limits which CAs may issue certs; absence means any CA could issue if they validate control.",
			Evidence:    "CAA query returned no records (or lookup skipped).",
			Remediation: "Publish CAA at DNS e.g. 0 issue \"letsencrypt.org\" for your zone.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
		})
	} else {
		var vals []string
		for _, rec := range result.CAARecords {
			vals = append(vals, rec.Tag+"="+rec.Value)
		}
		findings = append(findings, model.Finding{
			Code: "DNS-011", Severity: model.SeverityInfo, Title: "CAA records present",
			Description: "Certificate Authority Authorization records published for this name.",
			Evidence:    strings.Join(vals, ", "),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
		})
	}
	findings = append(findings, FamilyFindings(result.IPs)...)
	return findings
}
