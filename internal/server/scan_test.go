package server

import (
	"net/http"
	"testing"
)

func TestRunScan_Validation(t *testing.T) {
	tests := []struct {
		name       string
		opts       ScanOptions
		wantStatus int
		wantMsg    string
	}{
		{"empty url", ScanOptions{}, http.StatusBadRequest, "url is required"},
		{"bad profile", ScanOptions{URL: "https://example.com", Profile: "legacy"}, http.StatusBadRequest, "profile must be modern, strict, or fast"},
		{"bad ip_version", ScanOptions{URL: "https://example.com", Profile: "modern", IPVersion: "5"}, http.StatusBadRequest, "ip_version must be 4 or 6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, status, msg := RunScan(tt.opts)
			if rep != nil {
				t.Fatal("expected nil report")
			}
			if status != tt.wantStatus || msg != tt.wantMsg {
				t.Fatalf("status=%d msg=%q", status, msg)
			}
		})
	}
}
