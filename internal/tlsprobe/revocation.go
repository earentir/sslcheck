package tlsprobe

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"sslcheck/internal/model"
)

func checkOCSPURLs(chain []*x509.Certificate) []model.Finding {
	if len(chain) < 2 { return nil }

	leaf := chain[0]
	issuer := chain[1]
	var findings []model.Finding

	for _, ocspURL := range leaf.OCSPServer {
		reqBody, err := ocsp.CreateRequest(leaf, issuer, nil)
		if err != nil { continue }

		req, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewReader(reqBody))
		if err != nil { continue }
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			findings = append(findings, model.Finding{
				Code: "TLS-080", Severity: model.SeverityLow, Title: "OCSP responder unreachable",
				Description: "Active check: POST to the cert’s OCSP URL failed from the scanner (network, firewall, or downtime).",
				Evidence: fmt.Sprintf("%s: %v", ocspURL, err),
				Remediation: "Ensure OCSP URLs are reachable; prefer stapling to reduce client dependency on responder uptime.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()

		parsed, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			findings = append(findings, model.Finding{
				Code: "TLS-081", Severity: model.SeverityLow, Title: "OCSP response unparseable",
				Description: "HTTP reply was not a valid OCSP response for this cert/issuer (wrong MIME, proxy HTML, truncated body).",
				Evidence: fmt.Sprintf("%s parse error: %v", ocspURL, err),
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
			continue
		}

		switch parsed.Status {
		case ocsp.Revoked:
			findings = append(findings, model.Finding{
				Code: "TLS-082", Severity: model.SeverityCritical, Title: "OCSP: certificate revoked",
				Description: "Live OCSP query returned revoked—browsers that check OCSP should reject this cert.",
				Evidence: ocspURL,
				Remediation: "Stop using this certificate; investigate compromise or CA revocation reason.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
		case ocsp.Unknown:
			findings = append(findings, model.Finding{
				Code: "TLS-083", Severity: model.SeverityMedium, Title: "OCSP: unknown status",
				Description: "Responder could not return good/revoked for this serial—may indicate mis-issued cert or CA issue.",
				Evidence: ocspURL,
				Remediation: "Contact CA; reissue cert if unknown persists.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
		}
	}
	return findings
}
