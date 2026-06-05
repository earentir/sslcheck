package runner

import (
	"fmt"
	"time"

	"sslcheck/internal/dnsprobe"
	"sslcheck/internal/httpprobe"
	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/policy"
	"sslcheck/internal/tlsprobe"
)

// Analyze builds a full report from agent-collected capture data (no target network I/O).
func Analyze(capture *model.Capture, opts Options) (*model.Report, error) {
	if capture == nil {
		return nil, fmt.Errorf("capture is nil")
	}
	start := time.Now()
	if t, err := time.Parse(time.RFC3339, capture.StartedAt); err == nil {
		start = t
	}

	report := &model.Report{
		URL:           capture.URL,
		Host:          capture.Host,
		Port:          capture.Port,
		DNS:           capture.DNS,
		Redirect:      capture.Redirect,
		RedirectChain: capture.RedirectChain,
		HTTP:          capture.HTTP,
		PhaseTimings:  append([]model.PhaseTiming(nil), capture.PhaseTimings...),
	}

	var lookupErr error
	if capture.DNSLookupErr != "" {
		lookupErr = fmt.Errorf("%s", capture.DNSLookupErr)
	}
	report.Findings = append(report.Findings, dnsprobe.DNSFindings(capture.Host, capture.DNS, lookupErr)...)

	if !capture.SkipHTTP {
		report.Findings = append(report.Findings, httpprobe.RedirectFindings(report.Redirect)...)
		if !capture.FastScan {
			report.Findings = append(report.Findings, httpprobe.RedirectChainFindings(capture.RedirectChain, capture.RedirectChainErr, capture.Host)...)
		}
		report.Findings = append(report.Findings, httpprobe.HTTPSFindings(report.HTTP)...)
	}

	tlsOpts := tlsprobe.Options{
		SkipActiveOCSP: opts.SkipActiveOCSP,
		Fast:           capture.FastScan,
	}
	for _, epCap := range capture.Endpoints {
		ep := tlsprobe.AnalyzeEndpoint(epCap, capture.Host, tlsOpts)
		report.Endpoints = append(report.Endpoints, ep)
		report.Findings = append(report.Findings, ep.Findings...)
	}
	augmentNET002WhenOtherFamilyWorks(report)

	for _, ep := range report.Endpoints {
		if ep.TLSHandshakeOK && len(ep.CertificateChainDetails) > 0 {
			report.CertificateChain = append([]model.ChainCertificateDetail(nil), ep.CertificateChainDetails...)
			report.ChainBuildNotes = append([]string(nil), ep.ChainBuildNotes...)
			if ep.CertSummary != nil {
				report.LeafDaysUntilExpiry = ep.CertSummary.DaysUntilExpiry
				report.LeafNotAfter = ep.CertSummary.NotAfter
			}
			break
		}
	}

	t := time.Now()
	report.Findings = append(report.Findings, finalizeReport(report)...)
	report.Findings = append(report.Findings, policy.ConsistencyFindings(report.Endpoints)...)
	report.Findings = append(report.Findings, policy.ApplyProfile(report, policy.ProfileByName(opts.ProfileName))...)
	report.PhaseTimings = append(report.PhaseTimings, model.PhaseTiming{
		Name: "Policy & finalize", DurationMS: time.Since(t).Milliseconds(),
	})
	model.SortFindings(report.Findings)
	report.StartedAt = capture.StartedAt
	if report.StartedAt == "" {
		report.StartedAt = start.UTC().Format(time.RFC3339)
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	report.DurationMS = time.Since(start).Milliseconds()
	report.Overall = policy.DeriveOverall(report.Findings)
	if opts.ScannerVersion != "" {
		report.ScannerVersion = opts.ScannerVersion
	}
	if opts.ScannerSourceURL != "" {
		report.ScannerSource = opts.ScannerSourceURL
	}
	logx.Debug("runner.Analyze complete", "overall", report.Overall, "findings", len(report.Findings))
	return report, nil
}
