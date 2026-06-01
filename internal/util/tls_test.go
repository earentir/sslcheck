package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestTLSVersionString(t *testing.T) {
	if got := TLSVersionString(tls.VersionTLS13); got != "TLS1.3" {
		t.Fatalf("got %q", got)
	}
	if got := TLSVersionString(0xffff); got != "0xffff" {
		t.Fatalf("got %q", got)
	}
}

func TestPublicKeyStrength_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := mustTestCert(t, key, time.Now(), time.Now().Add(24*time.Hour))
	if got := PublicKeyStrength(cert); got != "RSA-2048" {
		t.Fatalf("got %q", got)
	}
}

func mustTestCert(t *testing.T, key *rsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
