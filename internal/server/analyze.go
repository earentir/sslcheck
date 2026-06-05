package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/runner"
)

const maxAnalyzeBodyBytes = 32 << 20

// AnalyzeOptions is the POST /api/v1/analyze request body.
type AnalyzeOptions struct {
	URL            string         `json:"url"`
	Profile        string         `json:"profile"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	NoHTTP         bool           `json:"no_http"`
	NoActiveOCSP   bool           `json:"no_active_ocsp"`
	Capture        *model.Capture `json:"capture"`
}

func defaultAnalyzeOptions() AnalyzeOptions {
	return AnalyzeOptions{Profile: "modern", TimeoutSeconds: 12}
}

// RunAnalyze validates input and returns a report from pre-collected capture data.
func RunAnalyze(opts AnalyzeOptions) (*model.Report, int, string) {
	opts.URL = strings.TrimSpace(opts.URL)
	if opts.URL == "" {
		return nil, http.StatusBadRequest, "url is required"
	}
	if opts.Capture == nil {
		return nil, http.StatusBadRequest, "capture is required"
	}
	if opts.Profile != "modern" && opts.Profile != "strict" && opts.Profile != "fast" {
		return nil, http.StatusBadRequest, "profile must be modern, strict, or fast"
	}
	if opts.TimeoutSeconds < 5 {
		opts.TimeoutSeconds = 5
	}
	if opts.TimeoutSeconds > 120 {
		opts.TimeoutSeconds = 120
	}

	runOpts := runner.Options{
		ProfileName:      opts.Profile,
		SkipHTTP:         opts.NoHTTP,
		SkipActiveOCSP:   opts.NoActiveOCSP,
		ScannerVersion:   scannerVersion,
		ScannerSourceURL: scannerSource,
	}
	if opts.Capture.URL == "" {
		opts.Capture.URL = opts.URL
	}
	logx.Info("API analyze start", "url", opts.URL, "endpoints", len(opts.Capture.Endpoints))
	rep, err := runner.Analyze(opts.Capture, runOpts)
	if err != nil {
		logx.Error("API analyze failed", "url", opts.URL, "err", err.Error())
		return nil, http.StatusBadRequest, err.Error()
	}
	logx.Info("API analyze done", "url", opts.URL, "overall", rep.Overall)
	return rep, http.StatusOK, ""
}

// HandleAnalyzePOST accepts agent capture JSON and returns the same report shape as /scan.
func HandleAnalyzePOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logx.Info("analyze POST", "remote", r.RemoteAddr, "content_length", r.ContentLength)
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAnalyzeBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("read body: %v", err))
		return
	}
	if len(body) > maxAnalyzeBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", maxAnalyzeBodyBytes))
		return
	}
	opts := defaultAnalyzeOptions()
	if err := json.Unmarshal(body, &opts); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
		return
	}
	rep, status, msg := RunAnalyze(opts)
	if rep == nil {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// HandleAnalyzeOPTIONS handles CORS preflight for /api/v1/analyze.
func HandleAnalyzeOPTIONS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodOptions {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
