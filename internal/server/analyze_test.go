package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sslcheck/internal/model"
)

func TestHandleAnalyzePOST_MinimalCapture(t *testing.T) {
	cap := model.Capture{
		URL:  "https://127.0.0.1/",
		Host: "127.0.0.1",
		Port: "443",
		DNS:  model.DNSResult{Host: "127.0.0.1", Port: "443", IPs: []string{"127.0.0.1"}},
	}
	body, _ := json.Marshal(AnalyzeOptions{
		URL:     "https://127.0.0.1/",
		Profile: "fast",
		Capture: &cap,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/analyze", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	HandleAnalyzePOST(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
