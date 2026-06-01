package tlsprobe

import (
	"crypto/tls"
	"crypto/x509"

	"sslcheck/internal/model"
)

// BuildCTSummary from handshake SCTs and cert embedded SCTs (lightweight; no log verification).
func BuildCTSummary(state tls.ConnectionState, chain []*x509.Certificate) *model.CertificateTransparencySummary {
	if len(chain) == 0 {
		return &model.CertificateTransparencySummary{
			SCTCount:      0,
			SCTSources:    nil,
			CTCompliance:  "unknown",
		}
	}
	sources := map[string]struct{}{}
	count := len(state.SignedCertificateTimestamps)
	if count > 0 {
		sources["tls_handshake"] = struct{}{}
	}
	leaf := chain[0]
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) { // embedded SCT OID
			sources["embedded"] = struct{}{}
		}
	}
	var srcList []string
	for s := range sources {
		srcList = append(srcList, s)
	}
	compliance := "unknown"
	switch {
	case count == 0 && len(srcList) == 0:
		compliance = "failed"
	case count > 0 || len(srcList) > 0:
		compliance = "likely_ok"
	}
	return &model.CertificateTransparencySummary{
		SCTCount:     count,
		SCTSources:   srcList,
		CTCompliance: compliance,
	}
}

func ctFindings(summary *model.CertificateTransparencySummary, ip string) []model.Finding {
	if summary == nil {
		return nil
	}
	var out []model.Finding
	switch summary.CTCompliance {
	case "failed":
		out = append(out, model.Finding{
			Code: "CERT-040", Severity: model.SeverityInfo, Title: "No SCTs in handshake",
			Description: "No embedded SCTs in the cert/handshake—CT may still be satisfied via logs or OCSP stapling.",
			Evidence:    "IP " + ip + " · sct_count=0",
			ReferenceURL: "https://certificate.transparency.dev/",
		})
	case "likely_ok":
		if summary.SCTCount == 0 {
			out = append(out, model.Finding{
				Code: "CERT-043", Severity: model.SeverityInfo, Title: "SCTs present (embedded extension)",
				Description: "Certificate carries CT extension; handshake SCT count was zero.",
				Evidence:    "IP " + ip + " · sources: " + joinStrings(summary.SCTSources),
				ReferenceURL: "https://certificate.transparency.dev/",
			})
		}
	}
	return out
}

func joinStrings(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	s := ss[0]
	for i := 1; i < len(ss); i++ {
		s += ", " + ss[i]
	}
	return s
}
