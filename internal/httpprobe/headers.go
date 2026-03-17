package httpprobe

import (
	"net/http"
	"strings"

	"sslcheck/internal/model"
)

func assessHeaders(h http.Header) []model.HeaderIssue {
	var issues []model.HeaderIssue

	csp := h.Get("Content-Security-Policy")
	if strings.TrimSpace(csp) == "" {
		issues = append(issues, model.HeaderIssue{Header: "Content-Security-Policy", Problem: "missing"})
	}
	xcto := strings.TrimSpace(h.Get("X-Content-Type-Options"))
	if !strings.EqualFold(xcto, "nosniff") {
		issues = append(issues, model.HeaderIssue{Header: "X-Content-Type-Options", Problem: "missing or non-standard", Observed: xcto})
	}
	rp := strings.TrimSpace(h.Get("Referrer-Policy"))
	if rp == "" {
		issues = append(issues, model.HeaderIssue{Header: "Referrer-Policy", Problem: "missing"})
	}
	xxp := strings.TrimSpace(h.Get("X-XSS-Protection"))
	if xxp != "" && !strings.EqualFold(xxp, "0") {
		issues = append(issues, model.HeaderIssue{Header: "X-XSS-Protection", Problem: "legacy header enabled", Observed: xxp})
	}
	if strings.TrimSpace(h.Get("Public-Key-Pins")) != "" {
		issues = append(issues, model.HeaderIssue{Header: "Public-Key-Pins", Problem: "deprecated (HPKP is deprecated; consider removing)", Observed: "present"})
	}
	if strings.TrimSpace(h.Get("Public-Key-Pins-Report-Only")) != "" {
		issues = append(issues, model.HeaderIssue{Header: "Public-Key-Pins-Report-Only", Problem: "deprecated (HPKP is deprecated; consider removing)", Observed: "present"})
	}
	return issues
}
