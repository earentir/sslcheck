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

func TestHandleChecksList_GET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/checks", nil)
	rr := httptest.NewRecorder()
	HandleChecksList(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Count  int `json:"count"`
		Checks []struct {
			Code string `json:"code"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Count == 0 || len(body.Checks) != body.Count {
		t.Fatalf("count=%d len=%d", body.Count, len(body.Checks))
	}
	if body.Checks[0].Code > body.Checks[len(body.Checks)-1].Code {
		t.Error("checks not sorted by code")
	}
}

func TestHandleCheckGet_Found(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/checks/CERT-011", nil)
	req.SetPathValue("code", "CERT-011")
	rr := httptest.NewRecorder()
	HandleCheckGet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "CERT-011" || body["severity"] != "critical" {
		t.Fatalf("body=%v", body)
	}
}

func TestHandleCheckGet_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/checks/NOPE-999", nil)
	req.SetPathValue("code", "NOPE-999")
	rr := httptest.NewRecorder()
	HandleCheckGet(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestHandleCheckGet_CaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/checks/cert-011", nil)
	req.SetPathValue("code", "cert-011")
	rr := httptest.NewRecorder()
	HandleCheckGet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
