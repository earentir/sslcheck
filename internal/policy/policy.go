package policy

import (
	"net"
	"sort"
	"strings"

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

func leafCertIdentity(cs *model.CertificateSummary) string {
	if cs == nil {
		return ""
	}
	return cs.SerialNumber + "|" + cs.SubjectCommonName + "|" + cs.NotAfter
}

func endpointIPFamily(ip string) int {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	if parsed.To4() != nil {
		return 4
	}
	return 6
}

func stringSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// dualStackIPv4IPv6LeafMismatch returns TLS-OK leaf identity sets per address family.
func dualStackIPv4IPv6LeafMismatch(endpoints []model.EndpointResult) (v4Leaves, v6Leaves map[string]struct{}) {
	v4Leaves = map[string]struct{}{}
	v6Leaves = map[string]struct{}{}
	for _, ep := range endpoints {
		if !ep.TLSHandshakeOK {
			continue
		}
		key := leafCertIdentity(ep.CertSummary)
		if key == "" {
			continue
		}
		switch endpointIPFamily(ep.IP) {
		case 4:
			v4Leaves[key] = struct{}{}
		case 6:
			v6Leaves[key] = struct{}{}
		}
	}
	return v4Leaves, v6Leaves
}

// dualStackIPv4IPv6LeafFindings reports when TLS succeeded on both IPv4 and IPv6 but the sets of
// observed leaf certificates differ between address families (serial|CN|notAfter).
// When both families each present exactly one distinct leaf and they differ, callers may suppress
// EDGE-003 as redundant with this finding.
func dualStackIPv4IPv6LeafFindings(v4Leaves, v6Leaves map[string]struct{}) []model.Finding {
	if len(v4Leaves) == 0 || len(v6Leaves) == 0 {
		return nil
	}
	if stringSetsEqual(v4Leaves, v6Leaves) {
		return nil
	}
	evidence := formatLeafSetsEvidence(v4Leaves, v6Leaves)
	return []model.Finding{{
		Code:        "EDGE-004",
		Severity:    model.SeverityHigh,
		Title:       "IPv4 vs IPv6 leaf certificate mismatch",
		Description: "The hostname resolves to both IPv4 and IPv6; TLS handshakes succeeded on each family but the presented leaf certificates are not the same set. Clients may see different identities or expiry depending on which path they use.",
		Evidence:    evidence,
		Remediation: "Serve the same certificate (and chain) on all published addresses, or ensure each path is intentional and documented (e.g. split renewal windows).",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
	}}
}

func formatLeafSetsEvidence(v4, v6 map[string]struct{}) string {
	v4s := sortedKeys(v4)
	v6s := sortedKeys(v6)
	return "IPv4 leaf cert(s) serial|CN|notAfter: " + strings.Join(v4s, "; ") +
		" · IPv6: " + strings.Join(v6s, "; ")
}

func sortedKeys(m map[string]struct{}) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

func ConsistencyFindings(endpoints []model.EndpointResult) []model.Finding {
	var findings []model.Finding
	if len(endpoints) < 2 { return findings }

	v4Leaves, v6Leaves := dualStackIPv4IPv6LeafMismatch(endpoints)
	findings = append(findings, dualStackIPv4IPv6LeafFindings(v4Leaves, v6Leaves)...)
	suppressEdge003 := len(findings) > 0 && len(v4Leaves) == 1 && len(v6Leaves) == 1

	versions := map[string][]string{}
	ciphers := map[string][]string{}
	leafs := map[string][]string{}
	for _, ep := range endpoints {
		if ep.TLSVersion != "" { versions[ep.TLSVersion] = append(versions[ep.TLSVersion], ep.IP) }
		if ep.CipherSuite != "" { ciphers[ep.CipherSuite] = append(ciphers[ep.CipherSuite], ep.IP) }
		if ep.CertSummary != nil {
			key := leafCertIdentity(ep.CertSummary)
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
	if len(leafs) > 1 && !suppressEdge003 {
		findings = append(findings, model.Finding{
			Code: "EDGE-003", Severity: model.SeverityHigh, Title: "Different certs per IP",
			Description: "At least two distinct leaf certs (serial/CN/expiry) across A/AAAA targets—may break pinning or indicate partial renewal.",
			Evidence: util.FormatMapIPs(leafs),
			Remediation: "Deploy identical chain to all nodes or document intentional split (e.g. geo) with valid SANs on each.",
			ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
		})
	}
	findings = append(findings, spkiConsistencyFindings(endpoints)...)
	return findings
}

func spkiConsistencyFindings(endpoints []model.EndpointResult) []model.Finding {
	if len(endpoints) < 2 {
		return nil
	}
	bySPKI := map[string][]string{}
	for _, ep := range endpoints {
		if !ep.TLSHandshakeOK || ep.CertSummary == nil || ep.CertSummary.SPKISHA256 == "" {
			continue
		}
		bySPKI[ep.CertSummary.SPKISHA256] = append(bySPKI[ep.CertSummary.SPKISHA256], ep.IP)
	}
	if len(bySPKI) <= 1 {
		return nil
	}
	return []model.Finding{{
		Code: "EDGE-005", Severity: model.SeverityMedium, Title: "Different public keys across IPs",
		Description: "Same hostname resolves to multiple IPs but TLS endpoints present different SPKI fingerprints.",
		Evidence: util.FormatMapIPs(bySPKI),
		Remediation: "Serve the same certificate/key on all published addresses unless split is intentional.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
	}}
}
