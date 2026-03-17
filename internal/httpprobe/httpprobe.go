package httpprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/tlsprobe"
)

func ProbeRedirect(ctx context.Context, httpsURL *url.URL) model.HTTPRedirectResult {
	httpURL := *httpsURL
	httpURL.Scheme = "http"
	if httpURL.Port() == "443" {
		httpURL.Host = httpURL.Hostname() + ":80"
	}

	result := model.HTTPRedirectResult{HTTPURL: httpURL.String()}
	logx.Debug("ProbeRedirect", "http_url", httpURL.String())
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL.String(), nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		logx.Debug("ProbeRedirect request failed", "err", err.Error())
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Location = resp.Header.Get("Location")
	logx.Debug("ProbeRedirect response", "status", result.StatusCode, "location", result.Location, "to_https", result.RedirectsToHTTPS)
	if result.Location != "" {
		if parsed, err := httpURL.Parse(result.Location); err == nil && strings.EqualFold(parsed.Scheme, "https") {
			result.RedirectsToHTTPS = true
		}
	}
	return result
}

func ProbeHTTPS(ctx context.Context, u *url.URL, timeout time.Duration) model.HTTPResult {
	result := model.HTTPResult{}
	logx.Debug("ProbeHTTPS GET", "url", u.String(), "timeout", timeout.String())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: u.Hostname(),
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Timeout: timeout, Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		logx.Warn("ProbeHTTPS failed", "url", u.String(), "err", err.Error())
		return result
	}
	defer resp.Body.Close()

	result.FinalURL = resp.Request.URL.String()
	logx.Info("ProbeHTTPS OK", "final_url", result.FinalURL, "status", result.StatusCode, "proto", result.Protocol, "server", result.Server)
	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")
	result.HSTS = resp.Header.Get("Strict-Transport-Security")
	result.AltSvc = resp.Header.Get("Alt-Svc")
	result.Protocol = resp.Proto
	result.HeaderIssues = assessHeaders(resp.Header)
	if result.HSTS != "" {
		parseHSTS(result.HSTS, &result)
	}
	result.CookieIssues = assessCookies(resp.Cookies())
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))

	result.SubresourceRefs = discoverSubresources(body, resp.Request.URL)
	result.MixedContentHits = mixedContentFromRefs(result.SubresourceRefs)

	active := activeHTTPSHosts(result.SubresourceRefs, resp.Request.URL.Hostname())
	logx.Debug("subresource TLS probes", "count", len(active))
	for _, host := range active {
		sr := tlsprobe.ProbeSubresourceHost(ctx, host, "443", timeout)
		result.SubresourceHosts = append(result.SubresourceHosts, sr)
	}
	sort.Slice(result.SubresourceHosts, func(i, j int) bool { return result.SubresourceHosts[i].Host < result.SubresourceHosts[j].Host })

	return result
}

func RedirectFindings(r model.HTTPRedirectResult) []model.Finding {
	var findings []model.Finding
	if r.Error != "" {
		findings = append(findings, model.Finding{
			Code: "HTTP-001", Severity: model.SeverityMedium, Title: "HTTP redirect check failed",
			Description: "The scanner could not complete a plain-HTTP GET to test redirect-to-HTTPS (network, timeout, or blocked).",
			Evidence:    r.Error,
			Remediation: "Ensure port 80 answers and allows the scanner; fix firewalls or redirects.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
		})
		return findings
	}
	if !r.RedirectsToHTTPS {
		findings = append(findings, model.Finding{
			Code: "HTTP-002", Severity: model.SeverityHigh, Title: "HTTP does not clearly redirect to HTTPS",
			Description: "A GET to the HTTP URL did not return a redirect whose Location points to https://. Users on port 80 may stay on cleartext HTTP.",
			Evidence:    fmt.Sprintf("HTTP URL probed: %s. status=%d Location=%q", r.HTTPURL, r.StatusCode, r.Location),
			Remediation: "Return 301/302/308 to https://same-host/… for all HTTP requests (or serve HSTS preload only after HTTPS works).",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides#http_redirections",
		})
	} else {
		findings = append(findings, model.Finding{
			Code: "HTTP-003", Severity: model.SeverityInfo, Title: "HTTP redirects to HTTPS",
			Description: "Plain HTTP responds with a redirect to an https:// URL.",
			Evidence:    fmt.Sprintf("%s → %s", r.HTTPURL, r.Location),
		})
	}
	return findings
}

func HTTPSFindings(r model.HTTPResult) []model.Finding {
	var findings []model.Finding
	if r.Error != "" {
		findings = append(findings, model.Finding{
			Code: "HTTP-010", Severity: model.SeverityMedium, Title: "HTTPS application probe failed",
			Description: "The scanner could not complete a GET over HTTPS (TLS OK at TCP layer may still fail at HTTP, or connection reset).",
			Evidence:    r.Error,
			Remediation: "Verify the site serves HTTP on 443 after TLS; check WAF, HTTP/2 issues, and app errors.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP",
		})
		return findings
	}

	hstsRef := "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"
	if r.HSTS == "" {
		findings = append(findings, model.Finding{
			Code: "HTTP-011", Severity: model.SeverityMedium, Title: "Strict-Transport-Security (HSTS) missing",
			Description: fmt.Sprintf("Final response URL %q had no Strict-Transport-Security header. Browsers will not remember to use only HTTPS for this host.", r.FinalURL),
			Evidence:    "Header Strict-Transport-Security absent on HTTPS response.",
			Remediation: "Add e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains (test first; preload is optional).",
			ReferenceURL: hstsRef,
		})
	} else {
		switch {
		case r.HSTSMaxAge == 0:
			findings = append(findings, model.Finding{
				Code: "HTTP-012", Severity: model.SeverityMedium, Title: "HSTS max-age=0 (clears HSTS)",
				Description: "Strict-Transport-Security includes max-age=0, telling browsers to drop HSTS for this host.",
				Evidence:    fmt.Sprintf("Raw header: %q", r.HSTS),
				Remediation: "Use max-age >= 31536000 for production HTTPS enforcement.",
				ReferenceURL: hstsRef,
			})
		case r.HSTSMaxAge < 31536000:
			findings = append(findings, model.Finding{
				Code: "HTTP-012", Severity: model.SeverityLow, Title: "HSTS max-age below one year",
				Description: "HSTS is present but max-age is under 31536000 seconds (1 year). Shorter values expire sooner and weaken protection.",
				Evidence:    fmt.Sprintf("max-age=%d. Raw: %q", r.HSTSMaxAge, r.HSTS),
				Remediation: "Increase max-age to at least 31536000 for stable public sites.",
				ReferenceURL: hstsRef,
			})
		}
		if !r.HSTSIncludeSubDomains {
			findings = append(findings, model.Finding{
				Code: "HTTP-013", Severity: model.SeverityInfo, Title: "HSTS without includeSubDomains",
				Description: "Subdomains are not covered by this host’s HSTS policy unless users visit them over HTTPS separately.",
				Evidence:    fmt.Sprintf("Header: %q", r.HSTS),
				Remediation: "Add includeSubDomains when all subdomains are HTTPS-ready.",
				ReferenceURL: hstsRef,
			})
		}
	}

	final := r.FinalURL
	if final == "" {
		final = "(unknown — HTTPS probe)"
	}
	for _, hi := range r.HeaderIssues {
		findings = append(findings, FindingFromHeaderIssue(hi, final))
	}

	for _, ci := range r.CookieIssues {
		findings = append(findings, model.Finding{
			Code: "HTTP-020", Severity: model.SeverityMedium, Title: "Cookie «" + ci.Name + "» missing security flags",
			Description: "Set-Cookie for this name lacks recommended attributes. Session/fixation and XSS risks increase when cookies are sent over HTTP or readable by JS.",
			Evidence:    fmt.Sprintf("Cookie name: %q. Issues: %s", ci.Name, strings.Join(ci.Problems, "; ")),
			Remediation: "Use Secure (HTTPS only), HttpOnly (no document.cookie) for session cookies, and SameSite=Lax or Strict unless you need cross-site POST cookies.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
		})
	}

	if len(r.MixedContentHits) > 0 {
		findings = append(findings, model.Finding{
			Code: "HTTP-030", Severity: model.SeverityHigh, Title: "Possible mixed content (HTTP/WS in HTML)",
			Description: "The HTML references resources or forms using http:// or ws:// while the page is HTTPS. Browsers may block active mixed content.",
			Evidence:    strings.Join(r.MixedContentHits, "; "),
			Remediation: "Change links, scripts, iframes, and forms to https:// or wss://, or use scheme-relative URLs where safe.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
		})
	}

	for _, sr := range r.SubresourceHosts {
		if sr.Error != "" || !sr.TLSOK || !sr.TrustOK || !sr.HostnameMatchOK {
			findings = append(findings, model.Finding{
				Code: "HTTP-031", Severity: model.SeverityHigh, Title: "Subresource host TLS problem: " + sr.Host,
				Description: "An active https:// subresource loaded from the page failed certificate validation or handshake from the scanner’s view.",
				Evidence: fmt.Sprintf("Host %q — tls_ok=%v trust_ok=%v hostname_match=%v error=%q IPs=%v",
					sr.Host, sr.TLSOK, sr.TrustOK, sr.HostnameMatchOK, sr.Error, sr.IPs),
				Remediation: "Serve a valid public cert for that hostname, full chain, and correct SANs; fix trust or name mismatch.",
				ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
			})
		}
	}

	if r.AltSvc != "" && strings.Contains(strings.ToLower(r.AltSvc), "h3=") {
		findings = append(findings, model.Finding{
			Code: "HTTP-040", Severity: model.SeverityInfo, Title: "HTTP/3 (QUIC) advertised via Alt-Svc",
			Description: "Alt-Svc suggests an HTTP/3 endpoint. Informational only.",
			Evidence:    r.AltSvc,
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Alt-Svc",
		})
	}
	return findings
}

func parseHSTS(header string, result *model.HTTPResult) {
	parts := strings.Split(header, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		l := strings.ToLower(p)
		if strings.HasPrefix(l, "max-age=") {
			var n int
			_, _ = fmt.Sscanf(l, "max-age=%d", &n)
			result.HSTSMaxAge = n
		}
		if l == "includesubdomains" { result.HSTSIncludeSubDomains = true }
		if l == "preload" { result.HSTSPreload = true }
	}
}
