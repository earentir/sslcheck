package runner

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"sslcheck/internal/testtls"
)

// TestReportContract_LocalTLS asserts stable JSON report-contract keys on a local fixture (no external network).
func TestReportContract_LocalTLS(t *testing.T) {
	srv := testtls.Start(t, testtls.Config{Names: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	rep, err := Run(ctx, "https://"+srv.Addr(), 15*time.Second, Options{
		ProfileName:    "modern",
		SkipHTTP:       true,
		SkipActiveOCSP: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	dns := doc["dns"].(map[string]any)
	if _, ok := dns["caa_satisfies_scan"]; !ok {
		t.Error("missing dns.caa_satisfies_scan")
	}
	if _, ok := dns["caa_records"]; !ok {
		t.Error("missing dns.caa_records")
	}
	if _, ok := dns["tlsa_records"]; !ok {
		t.Error("missing dns.tlsa_records")
	}

	eps := doc["endpoints"].([]any)
	if len(eps) == 0 {
		t.Fatal("no endpoints")
	}
	ep := eps[0].(map[string]any)
	for _, key := range []string{
		"weak_cipher_support", "ocsp_stapled", "ocsp_stapled_status",
		"certificate_transparency", "revocation",
	} {
		if _, ok := ep[key]; !ok {
			t.Errorf("missing endpoint.%s", key)
		}
	}
	rev := ep["revocation"].(map[string]any)
	if _, ok := rev["revocation_status"]; !ok {
		t.Error("missing revocation.revocation_status")
	}
	ct := ep["certificate_transparency"].(map[string]any)
	if _, ok := ct["ct_compliance"]; !ok {
		t.Error("missing certificate_transparency.ct_compliance")
	}
	if _, ok := doc["phase_timings"]; !ok {
		t.Error("missing phase_timings")
	}
}
