package tlsprobe

import (
	"crypto/x509"
	"fmt"

	"sslcheck/internal/model"
)

// peerCertCount is how many certs the server sent in the TLS handshake (before AIA fetch).
func lintChain(chain []*x509.Certificate, peerCertCount int) []model.Finding {
	var findings []model.Finding
	if len(chain) == 0 { return findings }

	leaf := chain[0]
	if leaf.IsCA {
		findings = append(findings, model.Finding{
			Code: "CERT-050", Severity: model.SeverityHigh, Title: "Leaf certificate marked as CA",
			Description: "BasicConstraints CA=true on the server leaf is wrong for TLS web server certs.",
			Evidence: fmt.Sprintf("subject %s", leaf.Subject.CommonName),
			Remediation: "Use an end-entity (EE) server certificate from your CA.",
			ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
		})
	}
	if !leaf.BasicConstraintsValid {
		findings = append(findings, model.Finding{
			Code: "CERT-051", Severity: model.SeverityMedium, Title: "Invalid basic constraints",
			Description: "Leaf basicConstraints extension missing or malformed.",
			Evidence: leaf.Subject.CommonName,
			Remediation: "Reissue certificate with valid Basic Constraints (CA:false for EE).",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9",
		})
	}
	if peerCertCount == 1 {
		findings = append(findings, model.Finding{
			Code: "CERT-052", Severity: model.SeverityMedium, Title: "No intermediates in handshake",
			Description: fmt.Sprintf("Server sent %d cert(s) in TLS—only leaf; clients may fail if they lack the intermediate.", peerCertCount),
			Evidence: fmt.Sprintf("leaf subject %s", leaf.Subject.CommonName),
			Remediation: "Concatenate full chain (leaf + intermediate(s)) in server config.",
			ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
		})
	}
	for i := 1; i < len(chain)-1; i++ {
		if !chain[i].IsCA {
			findings = append(findings, model.Finding{
				Code: "CERT-053", Severity: model.SeverityHigh, Title: "Non-CA in intermediate position",
				Description: "A certificate in the middle of the chain is not marked CA—path is invalid.",
				Evidence: fmt.Sprintf("position %d: %s", i, chain[i].Subject.CommonName),
				Remediation: "Reorder or replace chain so only CA certs appear between leaf and root.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-6.1",
			})
			break
		}
	}
	return findings
}
