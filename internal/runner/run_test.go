package runner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRun_InvalidURL(t *testing.T) {
	ctx := context.Background()
	opts := Options{ProfileName: "modern"}
	_, err := Run(ctx, "ftp://example.com", 5*time.Second, opts)
	if err == nil {
		t.Fatal("expected error for non-http(s) URL")
	}
}

func TestRun_HTTPBareHost_Normalizes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	ctx := context.Background()
	opts := Options{ProfileName: "modern", SkipHTTP: true, SkipActiveOCSP: true}
	rep, err := Run(ctx, "example.com", 15*time.Second, opts)
	if err != nil {
		t.Fatalf("bare hostname should normalize: %v", err)
	}
	if !strings.Contains(rep.URL, "example.com") {
		t.Errorf("URL = %q", rep.URL)
	}
}

func TestRun_ValidURL_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	ctx := context.Background()
	opts := Options{ProfileName: "modern", SkipActiveOCSP: true}
	rep, err := Run(ctx, "https://example.com", 15*time.Second, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.URL != "https://example.com/" && rep.URL != "https://example.com" {
		t.Errorf("report URL = %q", rep.URL)
	}
	if rep.Host != "example.com" {
		t.Errorf("report Host = %q", rep.Host)
	}
	if rep.Overall != "pass" && rep.Overall != "warn" && rep.Overall != "fail" {
		t.Errorf("report Overall = %q", rep.Overall)
	}
}
