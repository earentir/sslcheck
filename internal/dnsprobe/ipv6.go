package dnsprobe

import (
	"strings"

	"sslcheck/internal/model"
)

type IPFamilySummary struct {
	IPv4 []string
	IPv6 []string
}

func SplitIPFamilies(in []string) IPFamilySummary {
	var out IPFamilySummary
	for _, ip := range in {
		if isIPv6(ip) {
			out.IPv6 = append(out.IPv6, ip)
		} else {
			out.IPv4 = append(out.IPv4, ip)
		}
	}
	return out
}

func FamilyFindings(in []string) []model.Finding {
	fam := SplitIPFamilies(in)
	var findings []model.Finding
	switch {
	case len(fam.IPv4) > 0 && len(fam.IPv6) > 0:
		findings = append(findings, model.Finding{
			Code: "DNS-020", Severity: model.SeverityInfo, Title: "Dual-stack DNS (A + AAAA)",
			Description: "Both IPv4 and IPv6 addresses are published; clients and scanners may use either path.",
			Evidence:    "IPv4: " + strings.Join(fam.IPv4, ", ") + " · IPv6: " + strings.Join(fam.IPv6, ", "),
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/Dual-stack",
		})
	case len(fam.IPv6) > 0 && len(fam.IPv4) == 0:
		findings = append(findings, model.Finding{
			Code: "DNS-021", Severity: model.SeverityInfo, Title: "IPv6-only DNS (AAAA only)",
			Description: "No IPv4 A records; only IPv6-capable clients can connect unless a proxy/CDN fronts IPv4.",
			Evidence:    strings.Join(fam.IPv6, ", "),
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/IPv6",
		})
	case len(fam.IPv4) > 0 && len(fam.IPv6) == 0:
		findings = append(findings, model.Finding{
			Code: "DNS-022", Severity: model.SeverityInfo, Title: "IPv4-only DNS (no AAAA)",
			Description: "Only IPv4 addresses published; IPv6-only networks cannot reach this name via DNS as given.",
			Evidence:    strings.Join(fam.IPv4, ", "),
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/IPv6",
		})
	}
	return findings
}

func isIPv6(ip string) bool {
	for _, c := range ip {
		if c == ':' { return true }
	}
	return false
}
