package runner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"sslcheck/internal/dnsprobe"
	"sslcheck/internal/httpprobe"
	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/policy"
	"sslcheck/internal/tlsprobe"
	"sslcheck/internal/util"
)

// phaseContext gives each scan step its own deadline. Parent is ignored for timing so a slow DNS
// phase cannot cause later HTTP/TLS to fail instantly with "context deadline exceeded".
func phaseContext(_ context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

type Options struct {
	ProfileName    string
	SkipHTTP       bool
	SkipActiveOCSP bool
	FirstIPOnly    bool   // if true, only probe the first resolved IP
	ProxyURL       string // if set, connect via this HTTP CONNECT proxy (host:port or URL)
	// DNSServer is an optional recursive resolver (e.g. 1.1.1.1 or host:port). When set, all hostname
	// resolution in the scan (DNS phase, HTTP probes, subresource TLS, AIA, active OCSP) uses it; empty uses the OS resolver.
	DNSServer string
	// IPVersion is "", "4", or "6" — limit resolution and probing to IPv4 or IPv6 only.
	IPVersion string
	ScannerVersion   string // e.g. appVersion from main (JSON report + API)
	ScannerSourceURL string // project URL
}

func Run(parent context.Context, rawURL string, timeout time.Duration, opts Options) (*model.Report, error) {
	start := time.Now()
	logx.Debug("runner.Run start", "raw_url", rawURL, "timeout", timeout.String(), "profile", opts.ProfileName,
		"skip_http", opts.SkipHTTP, "skip_active_ocsp", opts.SkipActiveOCSP, "first_ip_only", opts.FirstIPOnly, "proxy", opts.ProxyURL != "",
		"dns_server_set", opts.DNSServer != "", "ip_version", opts.IPVersion)

	u, err := util.NormalizeURL(rawURL)
	if err != nil {
		logx.Warn("URL normalize failed", "raw", rawURL, "err", err.Error())
		return nil, err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	logx.Info("target resolved", "url", u.String(), "host", host, "port", port)

	report := &model.Report{
		URL:  u.String(),
		Host: host,
		Port: port,
		PhaseTimings: []model.PhaseTiming{},
	}

	recordPhase := func(name string, start time.Time) {
		report.PhaseTimings = append(report.PhaseTimings, model.PhaseTiming{
			Name:       name,
			DurationMS: time.Since(start).Milliseconds(),
		})
	}

	dnsOpts := dnsprobe.ResolveOptions{Server: opts.DNSServer}
	switch strings.TrimSpace(opts.IPVersion) {
	case "4":
		dnsOpts.IPNetwork = "ip4"
	case "6":
		dnsOpts.IPNetwork = "ip6"
	}
	dnsCtx, dnsCancel := phaseContext(parent, timeout)
	report.DNS, report.Findings = dnsprobe.ResolveHost(dnsCtx, host, port, dnsOpts, &report.PhaseTimings)
	dnsCancel()
	logx.Info("DNS phase done", "host", host, "ip_count", len(report.DNS.IPs), "lookup_ms", report.DNS.LookupMS, "findings", len(report.Findings))

	resolver := dnsprobe.ResolverForDNSServer(opts.DNSServer)
	ipVer := strings.TrimSpace(opts.IPVersion)
	fastScan := opts.ProfileName == "fast"

	if !opts.SkipHTTP {
		logx.Debug("HTTP probes starting", "host", host)
		t := time.Now()
		redCtx, redCancel := phaseContext(parent, timeout)
		report.Redirect = httpprobe.ProbeRedirect(redCtx, u, resolver, ipVer)
		redCancel()
		recordPhase("HTTP redirect (port 80)", t)
		report.Findings = append(report.Findings, httpprobe.RedirectFindings(report.Redirect)...)

		if !fastScan {
			t = time.Now()
			chainCtx, chainCancel := phaseContext(parent, timeout)
			chain, errStr := httpprobe.ProbeRedirectChain(chainCtx, u, resolver, ipVer)
			chainCancel()
			recordPhase("HTTP redirect chain", t)
			report.RedirectChain = chain
			report.Findings = append(report.Findings, httpprobe.RedirectChainFindings(chain, errStr, host)...)
		}

		t = time.Now()
		httpsCtx, httpsCancel := phaseContext(parent, timeout)
		report.HTTP = httpprobe.ProbeHTTPS(httpsCtx, u, timeout, resolver, ipVer, fastScan)
		httpsCancel()
		recordPhase("HTTPS GET", t)
		report.Findings = append(report.Findings, httpprobe.HTTPSFindings(report.HTTP)...)
		logx.Info("HTTP probes done", "host", host, "https_err", report.HTTP.Error != "", "redirect_chain_len", len(report.RedirectChain))
	} else {
		logx.Info("HTTP probes skipped", "host", host)
	}

	ips := report.DNS.IPs
	if opts.FirstIPOnly && len(ips) > 1 {
		logx.Info("first IP only", "host", host, "total_ips", len(ips), "using", ips[0])
		ips = ips[:1]
	}
	tlsOpts := tlsprobe.Options{
		SkipActiveOCSP: opts.SkipActiveOCSP,
		Fast:           fastScan,
		FetchHTTP:      httpprobe.FetchHTTPClient(timeout, resolver, ipVer),
	}
	if opts.ProxyURL != "" {
		logx.Debug("configuring proxy dialer", "proxy", opts.ProxyURL)
		dialer, err := proxyDialer(opts.ProxyURL)
		if err != nil {
			logx.Error("proxy dialer setup failed", "err", err.Error())
			return nil, err
		}
		tlsOpts.DialContext = dialer
	}
	probeOneIP := func(ip string) model.EndpointResult {
		t := time.Now()
		ep := tlsprobe.ProbeEndpoint(context.Background(), host, port, ip, timeout, tlsOpts)
		recordPhase(fmt.Sprintf("TLS probe %s", ip), t)
		return ep
	}
	if len(ips) <= 1 {
		for _, ip := range ips {
			logx.Info("TLS probe endpoint", "host", host, "ip", ip, "port", port)
			ep := probeOneIP(ip)
			report.Endpoints = append(report.Endpoints, ep)
			report.Findings = append(report.Findings, ep.Findings...)
		}
	} else {
		endpoints := make([]model.EndpointResult, len(ips))
		var phaseMu sync.Mutex
		var wg sync.WaitGroup
		for i, ip := range ips {
			logx.Info("TLS probe endpoint", "host", host, "ip", ip, "port", port)
			wg.Add(1)
			go func(i int, ip string) {
				defer wg.Done()
				t := time.Now()
				endpoints[i] = tlsprobe.ProbeEndpoint(context.Background(), host, port, ip, timeout, tlsOpts)
				phaseMu.Lock()
				report.PhaseTimings = append(report.PhaseTimings, model.PhaseTiming{
					Name:       fmt.Sprintf("TLS probe %s", ip),
					DurationMS: time.Since(t).Milliseconds(),
				})
				phaseMu.Unlock()
			}(i, ip)
		}
		wg.Wait()
		for _, ep := range endpoints {
			report.Endpoints = append(report.Endpoints, ep)
			report.Findings = append(report.Findings, ep.Findings...)
		}
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

	logx.Debug("policy consistency", "endpoints", len(report.Endpoints))
	t := time.Now()
	report.Findings = append(report.Findings, finalizeReport(report)...)
	report.Findings = append(report.Findings, policy.ConsistencyFindings(report.Endpoints)...)
	report.Findings = append(report.Findings, policy.ApplyProfile(report, policy.ProfileByName(opts.ProfileName))...)
	recordPhase("Policy & finalize", t)
	model.SortFindings(report.Findings)
	logx.Debug("runner.Run complete", "overall", report.Overall, "total_findings", len(report.Findings), "elapsed_ms", time.Since(start).Milliseconds())
	report.StartedAt = start.UTC().Format(time.RFC3339)
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	report.DurationMS = time.Since(start).Milliseconds()
	report.Overall = policy.DeriveOverall(report.Findings)
	if opts.ScannerVersion != "" {
		report.ScannerVersion = opts.ScannerVersion
	}
	if opts.ScannerSourceURL != "" {
		report.ScannerSource = opts.ScannerSourceURL
	}
	return report, nil
}

// proxyDialer returns a context-aware dialer that connects via the given HTTP CONNECT proxy.
func proxyDialer(proxyURLStr string) (tlsprobe.ContextDialer, error) {
	u, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Host == "" && u.Opaque != "" {
		u.Host = u.Opaque
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return &contextProxyDialer{d: d}, nil
}

// augmentNET002WhenOtherFamilyWorks clarifies NET-002 when e.g. IPv4 TLS works but IPv6 had no route.
func augmentNET002WhenOtherFamilyWorks(report *model.Report) {
	v4TLS := false
	v6TLS := false
	for _, ep := range report.Endpoints {
		if !ep.TLSHandshakeOK {
			continue
		}
		if ip := net.ParseIP(ep.IP); ip != nil {
			if ip.To4() != nil {
				v4TLS = true
			} else {
				v6TLS = true
			}
		}
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Code != "NET-002" {
			continue
		}
		if !strings.Contains(f.Evidence, "(tcp6)") {
			continue
		}
		if v4TLS {
			f.Description += " IPv4 TLS succeeded from this scanner, so the service is likely fine; this reflects IPv6 connectivity from your network."
		}
	}
	// Symmetric: IPv4 no-route but IPv6 works
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Code != "NET-002" || !strings.Contains(f.Evidence, "(tcp4)") {
			continue
		}
		if v6TLS {
			f.Description += " IPv6 TLS succeeded from this scanner, so the service is likely fine; this reflects IPv4 connectivity from your network."
		}
	}
}

type contextProxyDialer struct{ d proxy.Dialer }

func (c *contextProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := c.d.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return conn, nil
}
