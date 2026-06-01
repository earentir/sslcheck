package server

import (
	"net/http"

	"sslcheck/internal/logx"
	"sslcheck/internal/report"
)

// HandleChecksList returns all supported finding/check codes.
// GET /api/v1/checks
func HandleChecksList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logx.Debug("checks list", "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, report.ListChecks())
}

// HandleCheckGet returns catalog metadata for one finding code.
// GET /api/v1/checks/{code}
func HandleCheckGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	code := r.PathValue("code")
	if err := report.ValidateCheckCode(code); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	norm := report.NormalizeCheckCode(code)
	logx.Debug("check detail", "remote", r.RemoteAddr, "code", norm)
	def, ok := report.GetCheck(norm)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown check code: "+norm)
		return
	}
	writeJSON(w, http.StatusOK, def)
}
