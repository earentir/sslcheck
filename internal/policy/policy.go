package policy

import (
	"sslcheck/internal/model"
	"sslcheck/internal/util"
)

func DeriveOverall(findings []model.Finding) string {
	max := model.SeverityInfo
	for _, f := range findings {
		if model.SeverityRank(f.Severity) > model.SeverityRank(max) {
			max = f.Severity
		}
	}
	switch max {
	case model.SeverityCritical, model.SeverityHigh:
		return "fail"
	case model.SeverityMedium, model.SeverityLow:
		return "warn"
	default:
		return "pass"
	}
}

func ConsistencyFindings(endpoints []model.EndpointResult) []model.Finding {
	var findings []model.Finding
	if len(endpoints) < 2 { return findings }

	versions := map[string][]string{}
	ciphers := map[string][]string{}
	leafs := map[string][]string{}
	for _, ep := range endpoints {
		if ep.TLSVersion != "" { versions[ep.TLSVersion] = append(versions[ep.TLSVersion], ep.IP) }
		if ep.CipherSuite != "" { ciphers[ep.CipherSuite] = append(ciphers[ep.CipherSuite], ep.IP) }
		if ep.CertSummary != nil {
			key := ep.CertSummary.SerialNumber + "|" + ep.CertSummary.SubjectCommonName + "|" + ep.CertSummary.NotAfter
			leafs[key] = append(leafs[key], ep.IP)
		}
	}
	if len(versions) > 1 {
		findings = append(findings, model.Finding{
			Code: "EDGE-001", Severity: model.SeverityMedium, Title: "TLS version differs per IP",
			Description: "Same hostname resolves to multiple IPs but TLS max negotiated version is not uniform—users may get different security levels.",
			Evidence: util.FormatMapIPs(versions),
			Remediation: "Apply one TLS policy on all LBs and origins (same min/max protocol).",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
	if len(ciphers) > 1 {
		findings = append(findings, model.Finding{
			Code: "EDGE-002", Severity: model.SeverityLow, Title: "Cipher suite differs per IP",
			Description: "Different backends negotiated different ciphers—often mixed nginx/Apache versions or partial config rollout.",
			Evidence: util.FormatMapIPs(ciphers),
			Remediation: "Standardize cipher suite order and allowed list everywhere.",
			ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
		})
	}
	if len(leafs) > 1 {
		findings = append(findings, model.Finding{
			Code: "EDGE-003", Severity: model.SeverityHigh, Title: "Different certs per IP",
			Description: "At least two distinct leaf certs (serial/CN/expiry) across A/AAAA targets—may break pinning or indicate partial renewal.",
			Evidence: util.FormatMapIPs(leafs),
			Remediation: "Deploy identical chain to all nodes or document intentional split (e.g. geo) with valid SANs on each.",
			ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
		})
	}
	return findings
}
