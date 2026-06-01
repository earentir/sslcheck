package httpprobe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/netx"
)

// ProbeRedirectChain follows HTTP redirects on port 80. Resolver and ipVersion ("", "4", "6") control hostname resolution.
func ProbeRedirectChain(ctx context.Context, httpsURL *url.URL, resolver *net.Resolver, ipVersion string) ([]string, string) {
	httpURL := *httpsURL
	httpURL.Scheme = "http"
	if httpURL.Port() == "443" {
		httpURL.Host = httpURL.Hostname() + ":80"
	}
	var chain []string
	logx.Debug("ProbeRedirectChain start", "from", httpURL.String())
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		DialContext:     netx.HTTPDialContext(resolver, ipVersion, netx.TCPDialTimeout(10*time.Second)),
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			chain = append(chain, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL.String(), nil)
	if err != nil {
		return nil, err.Error()
	}
	chain = append(chain, req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		logx.Debug("ProbeRedirectChain error", "hops", len(chain), "err", err.Error())
		return dedupeChain(chain), err.Error()
	}
	defer resp.Body.Close()
	chain = append(chain, resp.Request.URL.String())
	out := dedupeChain(chain)
	logx.Debug("ProbeRedirectChain done", "hops", len(out))
	return out, ""
}

func RedirectChainFindings(chain []string, errStr string, initialHost string) []model.Finding {
	if errStr != "" {
		return []model.Finding{{
			Code: "HTTP-004", Severity: model.SeverityLow, Title: "Redirect chain inspection incomplete",
			Description: "Following HTTP redirects from port 80 stopped early (timeout, reset, or too many hops).",
			Evidence:    errStr + ". Partial chain: " + strings.Join(chain, " → "),
			Remediation: "Ensure HTTP is reachable and returns stable redirects to HTTPS.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
		}}
	}
	var findings []model.Finding
	for i, hop := range chain {
		if strings.HasPrefix(strings.ToLower(hop), "http://") && i > 0 {
			findings = append(findings, model.Finding{
				Code: "HTTP-005", Severity: model.SeverityHigh, Title: "Redirect chain used HTTP after first hop",
				Description: "After the initial http:// request, a later Location sent the client back to http:// instead of staying on https://.",
				Evidence:    hop + " (full chain: " + strings.Join(chain, " → ") + ")",
				Remediation: "Use only https:// URLs in Location headers once traffic should be encrypted end-to-end.",
				ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
			})
		}
		if u, err := url.Parse(hop); err == nil && u.Hostname() != "" && !strings.EqualFold(u.Hostname(), initialHost) {
			findings = append(findings, model.Finding{
				Code: "HTTP-007", Severity: model.SeverityInfo, Title: "Redirect to different host",
				Description: "A redirect Location points to another hostname; ensure that host is intended and covered by your cert.",
				Evidence:    initialHost + " → " + u.Hostname() + " (hop: " + hop + ")",
			})
			break
		}
	}
	if len(chain) > 4 {
		findings = append(findings, model.Finding{
			Code: "HTTP-006", Severity: model.SeverityLow, Title: fmt.Sprintf("Long redirect chain (%d hops)", len(chain)),
			Description: "Many redirect hops; slower first load and harder to audit. Aim for one redirect to canonical HTTPS URL.",
			Evidence:    strings.Join(chain, " → "),
			Remediation: "Collapse redirects at CDN or origin to one or two hops where possible.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
		})
	}
	return findings
}

func dedupeChain(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok { continue }
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
