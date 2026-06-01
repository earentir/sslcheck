package runner

import (
	"sslcheck/internal/caa"
	"sslcheck/internal/dnsprobe"
	"sslcheck/internal/model"
)

// finalizeReport fills report-contract fields that need TLS + DNS together.
func finalizeReport(report *model.Report) []model.Finding {
	var extra []model.Finding
	var primary *model.EndpointResult
	for i := range report.Endpoints {
		ep := &report.Endpoints[i]
		if ep.TLSHandshakeOK && primary == nil {
			primary = ep
		}
	}
	if primary != nil && primary.CertSummary != nil {
		res, detail := caa.EvaluateFromIssuerNames(
			report.Host,
			report.DNS.CAARecords,
			primary.CertSummary.IssuerCommonName,
			nil,
		)
		report.DNS.CAASatisfiesScan = string(res)
		if res == caa.SatisfyPolicyMismatch {
			extra = append(extra, model.Finding{
				Code: "DNS-012", Severity: model.SeverityHigh, Title: "CAA policy does not authorize observed issuer",
				Description: "CAA records exist but do not authorize the certificate issuer presented during TLS.",
				Evidence: detail,
				Remediation: "Update CAA at DNS to include the issuing CA, or obtain a cert from an authorized CA.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
			})
		}
		spki := primary.CertSummary.SPKISHA256
		cert := primary.CertSummary.CertSHA256
		extra = append(extra, dnsprobe.TLSAFindings(report.Host, report.DNS.TLSARecords, spki, cert, true)...)
	} else if len(report.DNS.CAARecords) == 0 {
		report.DNS.CAASatisfiesScan = string(caa.SatisfyNoRecords)
	}
	return extra
}
