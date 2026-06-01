package tlsprobe

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"sslcheck/internal/model"
)

func certQualityFindings(chain []*x509.Certificate, host string, ip string) []model.Finding {
	if len(chain) == 0 {
		return nil
	}
	var out []model.Finding
	leaf := chain[0]
	out = append(out, ekuFindings(leaf, ip)...)
	out = append(out, wildcardSANFindings(leaf, host, ip)...)
	out = append(out, intermediateQualityFindings(chain, ip)...)
	out = append(out, shortLivedCertFinding(leaf, ip)...)
	return out
}

func shortLivedCertFinding(leaf *x509.Certificate, ip string) []model.Finding {
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	if days > 14 || days < 0 {
		return nil
	}
	return []model.Finding{{
		Code: "CERT-057", Severity: model.SeverityInfo, Title: "Short-lived certificate",
		Description: "Leaf validity is under 15 days—ensure automated renewal (ACME) is in place.",
		Evidence: fmt.Sprintf("IP %s · %d days until NotAfter", ip, days),
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
	}}
}

func ekuFindings(leaf *x509.Certificate, ip string) []model.Finding {
	var out []model.Finding
	hasServerAuth := false
	hasAny := false
	for _, eku := range leaf.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny:
			hasAny = true
		case x509.ExtKeyUsageServerAuth:
			hasServerAuth = true
		}
	}
	if hasAny {
		out = append(out, model.Finding{
			Code: "CERT-060", Severity: model.SeverityHigh, Title: "Extended key usage includes any",
			Description: "EKU anyExtendedKeyUsage on a TLS server cert is overly broad.",
			Evidence: "IP " + ip,
			Remediation: "Reissue with extKeyUsage serverAuth only.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12",
		})
	}
	if !hasServerAuth && len(leaf.ExtKeyUsage) > 0 {
		out = append(out, model.Finding{
			Code: "CERT-061", Severity: model.SeverityHigh, Title: "Missing serverAuth extended key usage",
			Description: "Leaf EKU does not include id-kp-serverAuth.",
			Evidence: "IP " + ip,
			Remediation: "Use a certificate with serverAuth EKU for HTTPS.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12",
		})
	}
	encOnly := leaf.KeyUsage&x509.KeyUsageKeyEncipherment != 0 &&
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0
	if encOnly {
		out = append(out, model.Finding{
			Code: "CERT-062", Severity: model.SeverityMedium, Title: "Encipherment-only key usage",
			Description: "Leaf keyUsage is encipherment without digitalSignature—unusual for modern TLS server certs.",
			Evidence: "IP " + ip,
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3",
		})
	}
	return out
}

func wildcardSANFindings(leaf *x509.Certificate, host string, ip string) []model.Finding {
	var out []model.Finding
	host = strings.ToLower(strings.TrimSpace(host))
	for _, san := range leaf.DNSNames {
		san = strings.ToLower(san)
		if !strings.HasPrefix(san, "*.") {
			continue
		}
		if strings.Count(san, "*") > 1 {
			out = append(out, model.Finding{
				Code: "CERT-063", Severity: model.SeverityMedium, Title: "Multiple wildcards in SAN",
				Description: "Certificate SAN contains more than one wildcard label.",
				Evidence: fmt.Sprintf("IP %s · SAN %q", ip, san),
				ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
			})
		}
		if host != "" && !hostMatchesWildcard(host, san) && strings.HasSuffix(host, strings.TrimPrefix(san, "*.")) {
			out = append(out, model.Finding{
				Code: "CERT-064", Severity: model.SeverityLow, Title: "Wildcard SAN may not cover requested host",
				Description: "Requested hostname may not match wildcard SAN depth rules.",
				Evidence: fmt.Sprintf("host=%q SAN=%q", host, san),
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6125",
			})
		}
	}
	return out
}

func hostMatchesWildcard(host, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	suffix := strings.TrimPrefix(pattern, "*")
	return strings.HasSuffix(host, suffix) && strings.Count(strings.TrimSuffix(host, suffix), ".") == 1
}

func intermediateQualityFindings(chain []*x509.Certificate, ip string) []model.Finding {
	var out []model.Finding
	now := time.Now()
	for i := 1; i < len(chain); i++ {
		c := chain[i]
		role := "intermediate"
		if i == len(chain)-1 {
			role = "root"
		}
		if role == "root" {
			continue
		}
		if now.After(c.NotAfter) {
			out = append(out, model.Finding{
				Code: "CERT-054", Severity: model.SeverityCritical, Title: "Expired intermediate in chain",
				Description: "An intermediate certificate in the built chain is past NotAfter.",
				Evidence: fmt.Sprintf("IP %s · %s expired %s", ip, c.Subject.CommonName, c.NotAfter.Format(time.RFC3339)),
				Remediation: "Replace intermediate or update server chain.",
				ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
			})
		}
		if strings.Contains(strings.ToUpper(c.SignatureAlgorithm.String()), "SHA1") ||
			strings.Contains(strings.ToUpper(c.SignatureAlgorithm.String()), "SHA-1") {
			out = append(out, model.Finding{
				Code: "CERT-055", Severity: model.SeverityMedium, Title: "SHA-1 signed intermediate",
				Description: "Intermediate uses SHA-1 signature algorithm.",
				Evidence: fmt.Sprintf("IP %s · %s", ip, c.Subject.CommonName),
				ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
			})
		}
		if c.PublicKeyAlgorithm == x509.RSA {
			if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() < 2048 {
				out = append(out, model.Finding{
					Code: "CERT-056", Severity: model.SeverityMedium, Title: "Weak RSA intermediate key",
					Description: "Intermediate RSA key is below 2048 bits.",
					Evidence: fmt.Sprintf("IP %s · %s · %d bits", ip, c.Subject.CommonName, pub.N.BitLen()),
					ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
				})
			}
		}
	}
	return out
}
