package runner

import (
	"context"
	"testing"
	"time"

	"sslcheck/internal/testtls"
)

func TestCollectAnalyze_ParityWithRun(t *testing.T) {
	srv := testtls.Start(t, testtls.Config{Names: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	url := "https://" + srv.Addr()
	opts := Options{
		ProfileName:    "fast",
		SkipHTTP:       true,
		SkipActiveOCSP: true,
		ScannerVersion: "test",
	}

	runRep, err := Run(ctx, url, 15*time.Second, opts)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := Collect(ctx, url, 15*time.Second, opts)
	if err != nil {
		t.Fatal(err)
	}
	analyzeRep, err := Analyze(cap, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !analyzeRep.Endpoints[0].TLSHandshakeOK {
		t.Fatalf("analyze TLS failed: %v", analyzeRep.Endpoints[0].Errors)
	}
	if runRep.Overall != analyzeRep.Overall {
		t.Fatalf("overall run=%q analyze=%q", runRep.Overall, analyzeRep.Overall)
	}
	if len(runRep.Findings) != len(analyzeRep.Findings) {
		t.Fatalf("finding count run=%d analyze=%d", len(runRep.Findings), len(analyzeRep.Findings))
	}
}
