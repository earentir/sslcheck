package tlsprobe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"sslcheck/internal/model"
)

func testLeaf(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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

func findingCode(findings []model.Finding, code string) *model.Finding {
	for i := range findings {
		if findings[i].Code == code {
			return &findings[i]
		}
	}
	return nil
}

func TestAnalyzeCertificates_ExpirySeverities(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		notAfter time.Time
		wantCode string
		wantSev  model.Severity
	}{
		{"expired", now.Add(-24 * time.Hour), "CERT-011", model.SeverityCritical},
		{"soon", now.Add(3 * 24 * time.Hour), "CERT-012", model.SeverityMedium},
		{"approaching", now.Add(20 * 24 * time.Hour), "CERT-013", model.SeverityMedium},
		{"healthy", now.Add(90 * 24 * time.Hour), "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaf := testLeaf(t, now.Add(-time.Hour), tt.notAfter)
			_, findings := analyzeCertificates("example.com", []*x509.Certificate{leaf})
			if tt.wantCode == "" {
				for _, f := range findings {
					if f.Code == "CERT-011" || f.Code == "CERT-012" || f.Code == "CERT-013" {
						t.Fatalf("unexpected expiry finding %s", f.Code)
					}
				}
				return
			}
			f := findingCode(findings, tt.wantCode)
			if f == nil {
				t.Fatalf("missing %s in %#v", tt.wantCode, findings)
			}
			if f.Severity != tt.wantSev {
				t.Fatalf("%s severity=%s want %s", tt.wantCode, f.Severity, tt.wantSev)
			}
		})
	}
}

func TestTCPDialFinding_Routing(t *testing.T) {
	f := tcpDialFinding("tcp6", "2001:db8::1", errNoRoute)
	if f.Code != "NET-002" {
		t.Fatalf("got %s", f.Code)
	}
	f = tcpDialFinding("tcp4", "192.0.2.1", errConnRefused)
	if f.Code != "NET-001" {
		t.Fatalf("got %s", f.Code)
	}
}

type fakeNetErr string

func (e fakeNetErr) Error() string { return string(e) }

const (
	errNoRoute     fakeNetErr = "connect: no route to host"
	errConnRefused fakeNetErr = "connection refused"
)
