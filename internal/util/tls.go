package util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
)

func TLSVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func PublicKeyStrength(cert *x509.Certificate) string {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pk.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + pk.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func KeyUsageStrings(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 { out = append(out, "DigitalSignature") }
	if ku&x509.KeyUsageContentCommitment != 0 { out = append(out, "ContentCommitment") }
	if ku&x509.KeyUsageKeyEncipherment != 0 { out = append(out, "KeyEncipherment") }
	if ku&x509.KeyUsageDataEncipherment != 0 { out = append(out, "DataEncipherment") }
	if ku&x509.KeyUsageKeyAgreement != 0 { out = append(out, "KeyAgreement") }
	if ku&x509.KeyUsageCertSign != 0 { out = append(out, "CertSign") }
	if ku&x509.KeyUsageCRLSign != 0 { out = append(out, "CRLSign") }
	if ku&x509.KeyUsageEncipherOnly != 0 { out = append(out, "EncipherOnly") }
	if ku&x509.KeyUsageDecipherOnly != 0 { out = append(out, "DecipherOnly") }
	return out
}

func ExtKeyUsageStrings(in []x509.ExtKeyUsage) []string {
	var out []string
	for _, v := range in {
		switch v {
		case x509.ExtKeyUsageAny:
			out = append(out, "Any")
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		default:
			out = append(out, fmt.Sprintf("ExtKeyUsage(%d)", v))
		}
	}
	return out
}

func SubjectLine(cert *x509.Certificate) string {
	var parts []string
	if cert.Subject.CommonName != "" {
		parts = append(parts, "CN="+cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) > 0 {
		parts = append(parts, "O="+strings.Join(cert.Subject.Organization, ","))
	}
	if len(parts) == 0 {
		return cert.Subject.String()
	}
	return strings.Join(parts, ", ")
}

func FormatMapIPs(m map[string][]string) string {
	var keys []string
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		ips := append([]string(nil), m[k]...)
		sort.Strings(ips)
		parts = append(parts, fmt.Sprintf("%s=[%s]", k, strings.Join(ips, ",")))
	}
	return strings.Join(parts, " ")
}
