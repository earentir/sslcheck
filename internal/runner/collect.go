package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"sslcheck/internal/dnsprobe"
	"sslcheck/internal/httpprobe"
	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/tlsprobe"
	"sslcheck/internal/util"
)

// Collect runs DNS/HTTP/TLS network probes and returns capture data for server-side analysis.
func Collect(parent context.Context, rawURL string, timeout time.Duration, opts Options) (*model.Capture, error) {
	start := time.Now()
	u, err := util.NormalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	logx.Info("collect start", "url", u.String(), "host", host, "port", port)

	cap := &model.Capture{
		URL:          u.String(),
		Host:         host,
		Port:         port,
		StartedAt:    start.UTC().Format(time.RFC3339),
		PhaseTimings: []model.PhaseTiming{},
		SkipHTTP:     opts.SkipHTTP,
		FastScan:     opts.ProfileName == "fast",
	}

	recordPhase := func(name string, t time.Time) {
		cap.PhaseTimings = append(cap.PhaseTimings, model.PhaseTiming{
			Name: name, DurationMS: time.Since(t).Milliseconds(),
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
	dnsResult, lookupErr := dnsprobe.ResolveHostCollect(dnsCtx, host, port, dnsOpts, &cap.PhaseTimings)
	dnsCancel()
	cap.DNS = dnsResult
	if lookupErr != nil {
		cap.DNSLookupErr = lookupErr.Error()
	}

	resolver := dnsprobe.ResolverForDNSServer(opts.DNSServer)
	ipVer := strings.TrimSpace(opts.IPVersion)
	fastScan := opts.ProfileName == "fast"

	if !opts.SkipHTTP {
		t := time.Now()
		redCtx, redCancel := phaseContext(parent, timeout)
		cap.Redirect = httpprobe.ProbeRedirect(redCtx, u, resolver, ipVer)
		redCancel()
		recordPhase("HTTP redirect (port 80)", t)

		if !fastScan {
			t = time.Now()
			chainCtx, chainCancel := phaseContext(parent, timeout)
			chain, errStr := httpprobe.ProbeRedirectChain(chainCtx, u, resolver, ipVer)
			chainCancel()
			recordPhase("HTTP redirect chain", t)
			cap.RedirectChain = chain
			cap.RedirectChainErr = errStr
		}

		t = time.Now()
		httpsCtx, httpsCancel := phaseContext(parent, timeout)
		cap.HTTP = httpprobe.ProbeHTTPS(httpsCtx, u, timeout, resolver, ipVer, fastScan)
		httpsCancel()
		recordPhase("HTTPS GET", t)
	}

	ips := cap.DNS.IPs
	if opts.FirstIPOnly && len(ips) > 1 {
		ips = ips[:1]
	}
	tlsOpts := tlsprobe.Options{
		SkipActiveOCSP: opts.SkipActiveOCSP,
		Fast:           fastScan,
		FetchHTTP:      httpprobe.FetchHTTPClient(timeout, resolver, ipVer),
	}
	if opts.ProxyURL != "" {
		dialer, err := proxyDialer(opts.ProxyURL)
		if err != nil {
			return nil, err
		}
		tlsOpts.DialContext = dialer
	}

	collectOne := func(ip string) model.EndpointCapture {
		t := time.Now()
		ep := tlsprobe.ProbeEndpointCollect(context.Background(), host, port, ip, timeout, tlsOpts)
		recordPhase(fmt.Sprintf("TLS probe %s", ip), t)
		return ep
	}

	if len(ips) <= 1 {
		for _, ip := range ips {
			cap.Endpoints = append(cap.Endpoints, collectOne(ip))
		}
	} else {
		endpoints := make([]model.EndpointCapture, len(ips))
		var phaseMu sync.Mutex
		var wg sync.WaitGroup
		for i, ip := range ips {
			wg.Add(1)
			go func(i int, ip string) {
				defer wg.Done()
				t := time.Now()
				endpoints[i] = tlsprobe.ProbeEndpointCollect(context.Background(), host, port, ip, timeout, tlsOpts)
				phaseMu.Lock()
				cap.PhaseTimings = append(cap.PhaseTimings, model.PhaseTiming{
					Name: fmt.Sprintf("TLS probe %s", ip), DurationMS: time.Since(t).Milliseconds(),
				})
				phaseMu.Unlock()
			}(i, ip)
		}
		wg.Wait()
		cap.Endpoints = append(cap.Endpoints, endpoints...)
	}

	return cap, nil
}
