package tlsprobe

import (
	"context"
	"testing"
	"time"

	"sslcheck/internal/model"
	"sslcheck/internal/testtls"
)

func probeOpts() Options {
	return Options{SkipActiveOCSP: true}
}

func hasCode(findings []model.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestProbeEndpoint_ValidTLS_LocalServer(t *testing.T) {
	ep := testtls.Start(t, testtls.Config{Names: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res := ProbeEndpoint(ctx, ep.PrimaryName(), ep.Port, ep.IP, 10*time.Second, probeOpts())
	if !res.TLSHandshakeOK {
		t.Fatalf("handshake failed: %v", res.Errors)
	}
	if res.TLSVersion != "TLS1.2" && res.TLSVersion != "TLS1.3" {
		t.Fatalf("unexpected TLS version %q", res.TLSVersion)
	}
	if res.CertSummary == nil {
		t.Fatal("expected cert summary")
	}
	// Self-signed: trust check fails; hostname for IP should still verify.
	if !res.CertSummary.HostnameVerified {
		t.Errorf("hostname not verified: %s", res.CertSummary.HostnameVerifyError)
	}
	if hasCode(res.Findings, "CERT-011") {
		t.Error("unexpected expired cert on valid server")
	}
}

func TestProbeEndpoint_ExpiredCert_LocalServer(t *testing.T) {
	now := time.Now()
	ep := testtls.Start(t, testtls.Config{
		Names:     []string{"127.0.0.1"},
		NotBefore: now.Add(-48 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res := ProbeEndpoint(ctx, ep.PrimaryName(), ep.Port, ep.IP, 10*time.Second, probeOpts())
	if !res.TLSHandshakeOK {
		t.Fatalf("handshake should still complete with InsecureSkipVerify: %v", res.Errors)
	}
	if !hasCode(res.Findings, "CERT-011") {
		t.Fatalf("expected CERT-011, findings: %#v", res.Findings)
	}
	f := findingByCode(res.Findings, "CERT-011")
	if f.Severity != model.SeverityCritical {
		t.Fatalf("CERT-011 severity=%s want critical", f.Severity)
	}
}

func TestProbeEndpoint_HostnameMismatch_LocalServer(t *testing.T) {
	ep := testtls.Start(t, testtls.Config{Names: []string{"other.invalid"}})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res := ProbeEndpoint(ctx, "127.0.0.1", ep.Port, ep.IP, 10*time.Second, probeOpts())
	if !res.TLSHandshakeOK {
		t.Fatalf("handshake failed: %v", res.Errors)
	}
	if !hasCode(res.Findings, "CERT-020") {
		t.Fatalf("expected CERT-020 hostname mismatch, got %#v", res.Findings)
	}
}

func TestProbeEndpoint_LegacyTLS10_LocalServer(t *testing.T) {
	ep := testtls.Start(t, testtls.Config{
		Names:      []string{"127.0.0.1"},
		MinVersion: 0x0301, // TLS 1.0
		MaxVersion: 0x0301,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res := ProbeEndpoint(ctx, ep.PrimaryName(), ep.Port, ep.IP, 15*time.Second, probeOpts())
	if !res.TLSHandshakeOK {
		t.Fatalf("expected TLS1.0 handshake: %v", res.Errors)
	}
	if res.TLSVersion != "TLS1.0" {
		t.Fatalf("negotiated %q", res.TLSVersion)
	}
	if !hasCode(res.Findings, "TLS-010") && !hasCode(res.Findings, "TLS-011") {
		t.Fatalf("expected legacy TLS finding, got %#v", res.Findings)
	}
}

func findingByCode(findings []model.Finding, code string) model.Finding {
	for _, f := range findings {
		if f.Code == code {
			return f
		}
	}
	panic("finding " + code)
}
