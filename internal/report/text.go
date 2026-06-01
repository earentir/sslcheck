package report

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"sslcheck/internal/model"
)

// ShouldUseColor returns true if output should use ANSI colors: noColor is false,
// NO_COLOR env is not set, and out is a terminal.
func ShouldUseColor(noColor bool, out *os.File) bool {
	if noColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(out.Fd()))
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// Render formats the report as plain text. If useColor is true, overall result,
// section headers, and finding severities are colored for terminal output.
// If verbose is true, full redirect chain and extra detail are included.
// If debug is true, a scan phase timing table is appended at the end.
func Render(rep *model.Report, useColor bool, verbose bool, debug bool) string {
	var c *colors
	if useColor {
		c = &colors{}
	}
	return render(rep, c, verbose, debug)
}

// Grade returns an SSL Labs-style letter grade (A+ through F) from the report overall and findings.
func Grade(rep *model.Report) string {
	hasCritical := false
	hasHigh := false
	hasMedium := false
	hasLowOrInfo := false
	for _, f := range rep.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			hasCritical = true
		case model.SeverityHigh:
			hasHigh = true
		case model.SeverityMedium:
			hasMedium = true
		default:
			hasLowOrInfo = true
		}
	}
	switch rep.Overall {
	case "pass":
		if !hasLowOrInfo && !hasMedium {
			return "A+"
		}
		if !hasMedium {
			return "A"
		}
		return "A-"
	case "warn":
		if hasMedium {
			return "C"
		}
		return "B"
	case "fail":
		if hasCritical {
			return "F"
		}
		if hasHigh {
			return "D"
		}
		return "C"
	default:
		return "?"
	}
}

// QuietSummary returns a single line: overall result, grade, URL, and findings count.
func QuietSummary(rep *model.Report, useColor bool) string {
	n := len(rep.Findings)
	var overallStr string
	if useColor {
		c := &colors{}
		overallStr = c.overall(rep.Overall)
	} else {
		overallStr = strings.ToUpper(rep.Overall)
	}
	return fmt.Sprintf("%s (Grade: %s) %s (%d finding(s))\n", overallStr, Grade(rep), rep.URL, n)
}

type colors struct{}

func (c *colors) overall(s string) string {
	switch s {
	case "pass":
		return ansiGreen + "PASS" + ansiReset
	case "warn":
		return ansiYellow + "WARN" + ansiReset
	case "fail":
		return ansiRed + "FAIL" + ansiReset
	default:
		return strings.ToUpper(s)
	}
}

func (c *colors) severity(s model.Severity, text string) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return ansiRed + text + ansiReset
	case model.SeverityMedium:
		return ansiYellow + text + ansiReset
	case model.SeverityLow:
		return ansiDim + text + ansiReset
	case model.SeverityInfo:
		return ansiCyan + text + ansiReset
	default:
		return text
	}
}

func (c *colors) section(title string) string {
	if c == nil {
		return title
	}
	return ansiBold + title + ansiReset
}

func render(rep *model.Report, c *colors, verbose bool, debug bool) string {
	var b strings.Builder
	overallStr := rep.Overall
	if c != nil {
		overallStr = c.overall(rep.Overall)
	} else {
		overallStr = strings.ToUpper(rep.Overall)
	}
	fmt.Fprintf(&b, "Overall: %s (Grade: %s)\n", overallStr, Grade(rep))
	fmt.Fprintf(&b, "URL: %s\nHost: %s\nPort: %s\n", rep.URL, rep.Host, rep.Port)

	if len(rep.CertificateChain) > 0 {
		sec := "Certificate"
		if c != nil {
			sec = c.section("Certificate")
		}
		fmt.Fprintf(&b, "\n%s\n", sec)
		exp := rep.LeafDaysUntilExpiry
		expStr := fmt.Sprintf("%d day(s)", exp)
		if exp < 0 {
			expStr = fmt.Sprintf("EXPIRED (%d day(s) ago)", -exp)
		} else if exp == 0 {
			expStr = "expires today"
		}
		fmt.Fprintf(&b, "  Leaf validity: %s until %s\n", expStr, rep.LeafNotAfter)
		for _, note := range rep.ChainBuildNotes {
			fmt.Fprintf(&b, "  Chain: %s\n", note)
		}
		fmt.Fprintf(&b, "  Full chain (leaf → root):\n")
		for i, cert := range rep.CertificateChain {
			src := cert.Source
			switch src {
			case "from_server":
				src = "sent by server"
			case "fetched_aia":
				src = "fetched via AIA (missing from server bundle)"
			case "trust_anchor":
				src = "trust anchor (system store / verified path)"
			}
			d := cert.DaysUntilExpiry
			dStr := fmt.Sprintf("%d day(s)", d)
			if d < 0 {
				dStr = fmt.Sprintf("expired %d day(s) ago", -d)
			}
			fmt.Fprintf(&b, "  [%d] %s — %s\n", i+1, strings.ToUpper(cert.Role), cert.Subject)
			fmt.Fprintf(&b, "      Issuer: %s\n", cert.Issuer)
			fmt.Fprintf(&b, "      Serial: %s\n", cert.Serial)
			fmt.Fprintf(&b, "      Valid: %s .. %s (%s)\n", cert.NotBefore, cert.NotAfter, dStr)
			fmt.Fprintf(&b, "      Source: %s\n", src)
			fmt.Fprintf(&b, "      Public key: %s | Signature: %s | isCA: %v\n", cert.PublicKeyStrength, cert.SignatureAlgorithm, cert.IsCA)
			if len(cert.KeyUsage) > 0 {
				fmt.Fprintf(&b, "      Key usage: %s\n", strings.Join(cert.KeyUsage, ", "))
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	sec := "DNS"
	if c != nil {
		sec = c.section("DNS")
	}
	fmt.Fprintf(&b, "%s\n  Lookup: %d ms\n", sec, rep.DNS.LookupMS)
	if rep.DNS.CNAME != "" {
		fmt.Fprintf(&b, "  CNAME: %s\n", rep.DNS.CNAME)
	}
	fmt.Fprintf(&b, "  IPs: %s\n", strings.Join(rep.DNS.IPs, ", "))
	if len(rep.DNS.CAARecords) > 0 {
		fmt.Fprintf(&b, "  CAA:\n")
		for _, rec := range rep.DNS.CAARecords {
			fmt.Fprintf(&b, "    - flag=%d tag=%s value=%s\n", rec.Flag, rec.Tag, rec.Value)
		}
	}
	fmt.Fprintf(&b, "\n")

	sec = "HTTP redirect"
	if c != nil {
		sec = c.section("HTTP redirect")
	}
	fmt.Fprintf(&b, "%s\n  URL: %s\n", sec, rep.Redirect.HTTPURL)
	if rep.Redirect.Error != "" {
		fmt.Fprintf(&b, "  Error: %s\n\n", rep.Redirect.Error)
	} else {
		fmt.Fprintf(&b, "  Status: %d\n  Location: %s\n  Redirects to HTTPS: %v\n",
			rep.Redirect.StatusCode, rep.Redirect.Location, rep.Redirect.RedirectsToHTTPS)
		if verbose && len(rep.RedirectChain) > 0 {
			fmt.Fprintf(&b, "  Redirect chain:\n")
			for i, u := range rep.RedirectChain {
				fmt.Fprintf(&b, "    %d. %s\n", i+1, u)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	sec = "HTTPS application probe"
	if c != nil {
		sec = c.section("HTTPS application probe")
	}
	fmt.Fprintf(&b, "%s\n", sec)
	if rep.HTTP.Error != "" {
		fmt.Fprintf(&b, "  Error: %s\n\n", rep.HTTP.Error)
	} else {
		fmt.Fprintf(&b, "  Final URL: %s\n  Status: %d\n  Proto: %s\n  HSTS: %s\n",
			rep.HTTP.FinalURL, rep.HTTP.StatusCode, rep.HTTP.Protocol, rep.HTTP.HSTS)
		if rep.HTTP.AltSvc != "" {
			fmt.Fprintf(&b, "  Alt-Svc: %s\n", rep.HTTP.AltSvc)
		}
		if len(rep.HTTP.HeaderIssues) > 0 {
			fmt.Fprintf(&b, "  Header issues:\n")
			for _, hi := range rep.HTTP.HeaderIssues {
				fmt.Fprintf(&b, "    - %s: %s", hi.Header, hi.Problem)
				if hi.Observed != "" {
					fmt.Fprintf(&b, " (%s)", hi.Observed)
				}
				fmt.Fprintln(&b)
			}
		}
		if len(rep.HTTP.CookieIssues) > 0 {
			fmt.Fprintf(&b, "  Cookie issues:\n")
			for _, ci := range rep.HTTP.CookieIssues {
				fmt.Fprintf(&b, "    - %s: %s\n", ci.Name, strings.Join(ci.Problems, ", "))
			}
		}
		if len(rep.HTTP.MixedContentHits) > 0 {
			fmt.Fprintf(&b, "  Mixed content hits:\n")
			for _, hit := range rep.HTTP.MixedContentHits {
				fmt.Fprintf(&b, "    - %s\n", hit)
			}
		}
		if len(rep.HTTP.SubresourceHosts) > 0 {
			fmt.Fprintf(&b, "  Subresource hosts:\n")
			for _, sr := range rep.HTTP.SubresourceHosts {
				fmt.Fprintf(&b, "    - %s tls=%v trust=%v hostname=%v", sr.Host, sr.TLSOK, sr.TrustOK, sr.HostnameMatchOK)
				if sr.Error != "" {
					fmt.Fprintf(&b, " error=%s", sr.Error)
				}
				fmt.Fprintln(&b)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	sec = "Endpoints"
	if c != nil {
		sec = c.section("Endpoints")
	}
	fmt.Fprintf(&b, "%s\n", sec)
	for _, ep := range rep.Endpoints {
		fmt.Fprintf(&b, "  %s (%s)\n", ep.IP, ep.Network)
		fmt.Fprintf(&b, "    TCP reachable: %v\n", ep.TCPReachable)
		if ep.TCPConnectLatency != "" {
			fmt.Fprintf(&b, "    TCP latency: %s\n", ep.TCPConnectLatency)
		}
		fmt.Fprintf(&b, "    TLS handshake: %v\n", ep.TLSHandshakeOK)
		if ep.TLSHandshakeOK {
			fmt.Fprintf(&b, "    TLS version: %s\n    Cipher: %s\n    ALPN: %s\n", ep.TLSVersion, ep.CipherSuite, ep.ALPN)
			if ep.ALPNProbe != nil {
				fmt.Fprintf(&b, "    ALPN h2 accepted: %v\n    ALPN http/1.1 accepted: %v\n", ep.ALPNProbe.H2WhenOnly, ep.ALPNProbe.HTTP11WhenOnly)
			}
			if ep.Resumption != nil {
				fmt.Fprintf(&b, "    TLS1.2 resumed: %v\n    TLS1.3 resumed: %v\n", ep.Resumption.TLS12Resumed, ep.Resumption.TLS13Resumed)
			}
			if ep.CipherPreference != nil && ep.CipherPreference.Attempted {
				fmt.Fprintf(&b, "    Server cipher preference: %v\n", ep.CipherPreference.ServerPrefers)
			}
			fmt.Fprintf(&b, "    OCSP stapled: %v\n", ep.OCSPStapled)
			if ep.OCSPStatus != "" {
				fmt.Fprintf(&b, "    OCSP status: %s\n", ep.OCSPStatus)
			}
			fmt.Fprintf(&b, "    SCTs: %d\n", ep.SCTCount)
			if ep.CertSummary != nil {
				fmt.Fprintf(&b, "    Leaf CN: %s\n    SANs: %s\n    Issuer: %s\n",
					ep.CertSummary.SubjectCommonName,
					strings.Join(ep.CertSummary.DNSNames, ", "),
					ep.CertSummary.IssuerCommonName)
				fmt.Fprintf(&b, "    Expiry: %s (%d days)\n    Hostname verified: %v\n    Trust verified: %v\n",
					ep.CertSummary.NotAfter,
					ep.CertSummary.DaysUntilExpiry,
					ep.CertSummary.HostnameVerified,
					ep.CertSummary.TrustVerified)
				fmt.Fprintf(&b, "    Key: %s\n    Signature: %s\n",
					ep.CertSummary.PublicKeyStrength,
					ep.CertSummary.SignatureAlgorithm)
			}
		}
		if len(ep.ProtocolSupport) > 0 {
			fmt.Fprintf(&b, "    Protocol support: TLS1.0=%v TLS1.1=%v TLS1.2=%v TLS1.3=%v\n",
				ep.ProtocolSupport["TLS1.0"], ep.ProtocolSupport["TLS1.1"], ep.ProtocolSupport["TLS1.2"], ep.ProtocolSupport["TLS1.3"])
		}
		if len(ep.WeakCipherSupport) > 0 {
			fmt.Fprintf(&b, "    Weak ciphers accepted: %s\n", strings.Join(ep.WeakCipherSupport, ", "))
		}
		if ep.NoSNIHandshakeOK {
			fmt.Fprintf(&b, "    No-SNI handshake: true\n")
		} else if ep.TLSErrorNoSNI != "" {
			fmt.Fprintf(&b, "    No-SNI handshake error: %s\n", ep.TLSErrorNoSNI)
		}
	}

	sec = "Findings"
	if c != nil {
		sec = c.section("Findings")
	}
	fmt.Fprintf(&b, "\n%s\n", sec)
	if len(rep.Findings) == 0 {
		fmt.Fprintf(&b, "  none\n")
	} else {
		for _, f := range rep.Findings {
			sevStr := strings.ToUpper(string(f.Severity))
			if c != nil {
				sevStr = c.severity(f.Severity, sevStr)
			}
			fmt.Fprintf(&b, "  [%s] %s %s\n    %s\n", sevStr, f.Code, f.Title, f.Description)
			if f.Evidence != "" {
				fmt.Fprintf(&b, "    Evidence: %s\n", f.Evidence)
			}
			if f.Remediation != "" {
				fmt.Fprintf(&b, "    Remediation: %s\n", f.Remediation)
			}
			if f.ReferenceURL != "" {
				fmt.Fprintf(&b, "    Reference: %s\n", f.ReferenceURL)
			}
		}
	}
	if debug {
		if table := RenderPhaseTimingsTable(rep.PhaseTimings, rep.DurationMS); table != "" {
			fmt.Fprintf(&b, "\n%s\n", table)
		}
	}
	return b.String()
}
