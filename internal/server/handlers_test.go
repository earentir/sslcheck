package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealth_GET(t *testing.T) {
	SetScannerMeta("test-ver", "https://example.test/sslcheck")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	HandleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" || body["scanner_version"] != "test-ver" {
		t.Fatalf("body=%v", body)
	}
}

func TestHandleHealth_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	HandleHealth(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestHandleSchema_GET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/schema", nil)
	rr := httptest.NewRecorder()
	HandleSchema(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
