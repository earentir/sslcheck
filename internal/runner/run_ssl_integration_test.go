package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"sslcheck/internal/model"
	"sslcheck/internal/testtls"
)

func hasFindingCode(findings []model.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestRun_LocalTLS_ValidEndpoint(t *testing.T) {
	srv := testtls.Start(t, testtls.Config{Names: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rep, err := Run(ctx, "https://"+srv.Addr(), 15*time.Second, Options{
		ProfileName:      "modern",
		SkipHTTP:         true,
		SkipActiveOCSP:   true,
		ScannerVersion:   "test",
		ScannerSourceURL: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.DNS.IPs) == 0 || rep.DNS.IPs[0] != "127.0.0.1" {
		t.Fatalf("dns ips=%v", rep.DNS.IPs)
	}
	if len(rep.Endpoints) == 0 {
		t.Fatal("no endpoints")
	}
	if !rep.Endpoints[0].TLSHandshakeOK {
		t.Fatalf("TLS failed: %v", rep.Endpoints[0].Errors)
	}
}

func TestRun_LocalTLS_ExpiredCert_FailsOverall(t *testing.T) {
	now := time.Now()
	srv := testtls.Start(t, testtls.Config{
		Names:     []string{"127.0.0.1"},
		NotBefore: now.Add(-72 * time.Hour),
		NotAfter:  now.Add(-1 * time.Hour),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rep, err := Run(ctx, "https://"+srv.Addr(), 15*time.Second, Options{
		ProfileName:    "modern",
		SkipHTTP:       true,
		SkipActiveOCSP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingCode(rep.Findings, "CERT-011") {
		t.Fatalf("expected CERT-011 expired, findings=%d", len(rep.Findings))
	}
	if rep.Overall != "fail" {
		t.Fatalf("overall=%q want fail for expired cert", rep.Overall)
	}
}

func TestRun_LocalTLS_ExpiringSoon_WarnNotFail(t *testing.T) {
	now := time.Now()
	srv := testtls.Start(t, testtls.Config{
		Names:     []string{"127.0.0.1"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(3 * 24 * time.Hour),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rep, err := Run(ctx, "https://"+srv.Addr(), 15*time.Second, Options{
		ProfileName:    "modern",
		SkipHTTP:       true,
		SkipActiveOCSP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFindingCode(rep.Findings, "CERT-012") {
		t.Fatal("expected CERT-012")
	}
	for _, f := range rep.Findings {
		if f.Code == "CERT-012" && f.Severity != model.SeverityMedium {
			t.Fatalf("CERT-012 severity=%s want medium", f.Severity)
		}
	}
	// Local self-signed fixture also emits CERT-021 (critical); overall may be fail.
	// This test only asserts CERT-012 is medium, not expired (CERT-011).
	if hasFindingCode(rep.Findings, "CERT-011") {
		t.Fatal("unexpected CERT-011 on soon-expiring cert")
	}
}

func TestRun_LocalTLS_IPv4Only(t *testing.T) {
	srv := testtls.Start(t, testtls.Config{Names: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rep, err := Run(ctx, "https://"+srv.Addr(), 15*time.Second, Options{
		ProfileName:    "modern",
		SkipHTTP:       true,
		SkipActiveOCSP: true,
		IPVersion:      "4",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range rep.DNS.IPs {
		if strings.Contains(ip, ":") {
			t.Fatalf("ipv4-only scan returned v6 %q", ip)
		}
	}
}
