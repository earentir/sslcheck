package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/report"
	"sslcheck/internal/runner"
)

// ScanOptions mirrors CLI scan options for API requests.
type ScanOptions struct {
	URL            string `json:"url"`
	Profile        string `json:"profile"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	NoHTTP         bool   `json:"no_http"`
	NoActiveOCSP   bool   `json:"no_active_ocsp"`
	FirstIPOnly    bool   `json:"first_ip_only"`
	ProxyURL       string `json:"proxy_url"`
}

func defaultScanOptions() ScanOptions {
	return ScanOptions{
		Profile:        "modern",
		TimeoutSeconds: 12,
	}
}

// RunScan executes a single-URL scan and returns the report or an error string for HTTP layer.
func RunScan(ctx context.Context, opts ScanOptions) (*model.Report, int, string) {
	opts.URL = strings.TrimSpace(opts.URL)
	logx.Debug("RunScan", "url", opts.URL, "profile", opts.Profile, "timeout_sec", opts.TimeoutSeconds)
	if opts.URL == "" {
		logx.Warn("RunScan rejected: empty url")
		return nil, http.StatusBadRequest, "url is required"
	}
	if opts.Profile != "modern" && opts.Profile != "strict" {
		logx.Warn("RunScan rejected: bad profile", "profile", opts.Profile)
		return nil, http.StatusBadRequest, "profile must be modern or strict"
	}
	if opts.TimeoutSeconds < 5 {
		opts.TimeoutSeconds = 5
	}
	if opts.TimeoutSeconds > 120 {
		opts.TimeoutSeconds = 120
	}
	timeout := time.Duration(opts.TimeoutSeconds) * time.Second
	runOpts := runner.Options{
		ProfileName:      opts.Profile,
		SkipHTTP:         opts.NoHTTP,
		SkipActiveOCSP:   opts.NoActiveOCSP,
		FirstIPOnly:      opts.FirstIPOnly,
		ProxyURL:         strings.TrimSpace(opts.ProxyURL),
		ScannerVersion:   scannerVersion,
		ScannerSourceURL: scannerSource,
	}
	logx.Info("API scan start", "url", opts.URL, "timeout", timeout.String())
	rep, err := runner.Run(ctx, opts.URL, timeout, runOpts)
	if err != nil {
		logx.Error("API scan failed", "url", opts.URL, "err", err.Error())
		return nil, http.StatusBadRequest, err.Error()
	}
	logx.Info("API scan done", "url", opts.URL, "overall", rep.Overall, "duration_ms", rep.DurationMS)
	return rep, http.StatusOK, ""
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// HandleHealth returns 200 OK.
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logx.Debug("health check", "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":            "ok",
		"scanner_version":   scannerVersion,
		"scanner_source":    scannerSource,
	})
}

// HandleSchema returns the JSON schema for reports.
func HandleSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logx.Debug("schema request", "remote", r.RemoteAddr)
	b, err := report.JSONSchema()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}

// HandleScanPOST expects JSON body with ScanOptions (at minimum "url").
func HandleScanPOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logx.Info("scan POST", "remote", r.RemoteAddr, "content_length", r.ContentLength)
	opts := defaultScanOptions()
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		logx.Warn("scan POST bad JSON", "err", err.Error())
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
		return
	}
	ctx := r.Context()
	rep, status, msg := RunScan(ctx, opts)
	if rep == nil {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// HandleScanGET uses query: url, profile, timeout_seconds, no_http, no_active_ocsp, first_ip_only, proxy_url.
func HandleScanGET(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logx.Info("scan GET", "remote", r.RemoteAddr, "raw_query", r.URL.RawQuery)
	q := r.URL.Query()
	opts := defaultScanOptions()
	opts.URL = q.Get("url")
	if p := q.Get("profile"); p != "" {
		opts.Profile = p
	}
	if t := q.Get("timeout_seconds"); t != "" {
		var sec int
		_, _ = fmt.Sscanf(t, "%d", &sec)
		if sec > 0 {
			opts.TimeoutSeconds = sec
		}
	}
	opts.NoHTTP = q.Get("no_http") == "1" || strings.EqualFold(q.Get("no_http"), "true")
	opts.NoActiveOCSP = q.Get("no_active_ocsp") == "1" || strings.EqualFold(q.Get("no_active_ocsp"), "true")
	opts.FirstIPOnly = q.Get("first_ip_only") == "1" || strings.EqualFold(q.Get("first_ip_only"), "true")
	opts.ProxyURL = q.Get("proxy_url")

	ctx := r.Context()
	rep, status, msg := RunScan(ctx, opts)
	if rep == nil {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
