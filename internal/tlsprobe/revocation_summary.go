package tlsprobe

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sslcheck/internal/model"
)

var oidMustStaple = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

func hasMustStaple(leaf *x509.Certificate) bool {
	if leaf == nil {
		return false
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidMustStaple) {
			return true
		}
	}
	return false
}

func mustStapleFindings(stapled bool, stapleStatus string, ip string) []model.Finding {
	if !stapled || stapleStatus != "good" {
		return []model.Finding{{
			Code: "TLS-085", Severity: model.SeverityCritical, Title: "Must-Staple required but stapling missing or invalid",
			Description: "Certificate carries OCSP Must-Staple (TLS Feature) but handshake did not include a good stapled OCSP response.",
			Evidence:    fmt.Sprintf("IP %s · stapled=%v status=%q", ip, stapled, stapleStatus),
			Remediation: "Enable OCSP stapling on the server or remove Must-Staple from the certificate.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc7633",
		}}
	}
	return nil
}

func stapledOCSPFindings(status string, ip string) []model.Finding {
	switch status {
	case "revoked":
		return []model.Finding{{
			Code: "TLS-086", Severity: model.SeverityCritical, Title: "Stapled OCSP: certificate revoked",
			Description: "The stapled OCSP response indicates the certificate is revoked.",
			Evidence: "IP " + ip,
			Remediation: "Stop using this certificate immediately.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
		}}
	case "unknown", "parse_error":
		return []model.Finding{{
			Code: "TLS-087", Severity: model.SeverityHigh, Title: "Stapled OCSP status not good",
			Description: "Stapled OCSP response could not be validated as good (unknown or parse error).",
			Evidence: fmt.Sprintf("IP %s · status=%q", ip, status),
			Remediation: "Fix stapling configuration or reissue certificate.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
		}}
	}
	return nil
}

func checkCRL(ctx context.Context, chain []*x509.Certificate, httpClient *http.Client) (model.Finding, string) {
	if len(chain) == 0 {
		return model.Finding{}, "no_urls"
	}
	leaf := chain[0]
	if len(leaf.CRLDistributionPoints) == 0 {
		return model.Finding{
			Code: "CERT-042", Severity: model.SeverityInfo, Title: "No CRL distribution points",
			Description: "Leaf certificate has no CRLDistributionPoints extension.",
			Evidence: leaf.Subject.CommonName,
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3",
		}, "no_urls"
	}
	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	for _, u := range leaf.CRLDistributionPoints {
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		resp.Body.Close()
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			continue
		}
		if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(time.Now()) {
			continue
		}
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return model.Finding{
					Code: "TLS-088", Severity: model.SeverityCritical, Title: "CRL: certificate revoked",
					Description: "Fetched CRL lists this certificate serial as revoked.",
					Evidence: u,
					Remediation: "Stop using this certificate.",
					ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3",
				}, "revoked"
			}
		}
		return model.Finding{}, "good"
	}
	return model.Finding{
		Code: "TLS-089", Severity: model.SeverityLow, Title: "CRL fetch failed",
		Description: "Could not fetch or parse any CRL from distribution points.",
		Evidence: fmt.Sprintf("%d CRL DP(s) on leaf", len(leaf.CRLDistributionPoints)),
		Remediation: "Ensure CRL URLs are reachable; prefer OCSP stapling where possible.",
	}, "unreachable"
}

func buildRevocationSummary(
	leaf *x509.Certificate,
	stapled bool,
	stapleStatus string,
	activeFindings []model.Finding,
	crlChecked bool,
	crlStatus string,
	activeOCSPAttempted bool,
) *model.RevocationSummary {
	ms := hasMustStaple(leaf)
	active := activeOCSPStatusFromFindings(activeFindings)
	if active == "not_checked" && activeOCSPAttempted && len(leaf.OCSPServer) > 0 && len(activeFindings) == 0 {
		active = "good"
	}
	overall := "incomplete"
	switch {
	case stapleStatus == "revoked" || active == "revoked" || crlStatus == "revoked":
		overall = "revoked"
	case ms && (!stapled || stapleStatus != "good"):
		overall = "incomplete"
	case stapled && stapleStatus == "good":
		overall = "good"
	case active == "good" || crlStatus == "good":
		overall = "good"
	case active == "unknown" || stapleStatus == "unknown":
		overall = "unknown"
	default:
		overall = "incomplete"
	}
	stapleField := stapleStatus
	if !stapled {
		stapleField = "none"
	}
	return &model.RevocationSummary{
		StapledOCSP:             stapled,
		StapledOCSPStatus:       stapleField,
		ActiveOCSPStatus:        active,
		CRLChecked:              crlChecked,
		CRLStatus:               crlStatus,
		MustStapleRequired:      ms,
		OverallRevocationStatus: overall,
	}
}

func activeOCSPStatusFromFindings(findings []model.Finding) string {
	hasCheck := false
	for _, f := range findings {
		switch f.Code {
		case "TLS-082":
			return "revoked"
		case "TLS-083":
			hasCheck = true
		case "TLS-080", "TLS-081":
			hasCheck = true
		}
	}
	if hasCheck {
		for _, f := range findings {
			if f.Code == "TLS-083" {
				return "unknown"
			}
		}
		return "unreachable"
	}
	return "not_checked"
}
