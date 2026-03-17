package tlsprobe

import (
	"strings"
	"time"

	"crypto/x509"

	"sslcheck/internal/model"
	"sslcheck/internal/util"
)

func buildChainCertificateDetails(chain []*x509.Certificate, peerChain []*x509.Certificate, fetchedFP map[string]bool) []model.ChainCertificateDetail {
	if len(chain) == 0 {
		return nil
	}
	peerFP := certFingerprintSet(peerChain)
	if fetchedFP == nil {
		fetchedFP = make(map[string]bool)
	}
	var out []model.ChainCertificateDetail
	for i, c := range chain {
		fp := certFingerprint(c)
		role := chainCertRole(i, len(chain), c)
		source := "trust_anchor"
		if peerFP[fp] {
			source = "from_server"
		} else if fetchedFP[fp] {
			source = "fetched_aia"
		}
		days := int(time.Until(c.NotAfter).Hours() / 24)
		out = append(out, model.ChainCertificateDetail{
			Role:               role,
			Subject:            util.SubjectLine(c),
			Issuer:             issuerLine(c),
			Serial:             c.SerialNumber.Text(16),
			NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
			DaysUntilExpiry:    days,
			Source:             source,
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
			PublicKeyStrength:  util.PublicKeyStrength(c),
			KeyUsage:           util.KeyUsageStrings(c.KeyUsage),
			IsCA:               c.IsCA,
		})
	}
	return out
}

func chainCertRole(index, n int, c *x509.Certificate) string {
	if n == 1 {
		if c.Subject.String() == c.Issuer.String() {
			return "root"
		}
		return "leaf"
	}
	if index == 0 {
		return "leaf"
	}
	if index == n-1 {
		return "root"
	}
	return "intermediate"
}

func issuerLine(c *x509.Certificate) string {
	n := c.Issuer
	if n.CommonName != "" {
		return "CN=" + n.CommonName
	}
	if len(n.Organization) > 0 {
		return "O=" + strings.Join(n.Organization, ",")
	}
	return n.String()
}
