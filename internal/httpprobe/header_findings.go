package httpprobe

import (
	"fmt"
	"strings"

	"sslcheck/internal/model"
)

// mdn returns MDN HTTP header docs (stable paths).
func mdnHeader(name string) string {
	return "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/" + strings.ReplaceAll(name, " ", "-")
}

// FindingFromHeaderIssue builds a specific finding per security header check.
func FindingFromHeaderIssue(hi model.HeaderIssue, finalURL string) model.Finding {
	ev := fmt.Sprintf("Probe URL: %s. Header %q — issue: %s", finalURL, hi.Header, hi.Problem)
	if strings.TrimSpace(hi.Observed) != "" {
		ev += fmt.Sprintf(". Value seen: %q", hi.Observed)
	} else if hi.Problem == "missing" || strings.Contains(hi.Problem, "missing") {
		ev += ". No value sent (header absent or empty)."
	}

	switch hi.Header {
	case "Content-Security-Policy":
		return model.Finding{
			Code: "HTTP-015", Severity: model.SeverityMedium,
			Title: "Content-Security-Policy (CSP) missing",
			Description: "The HTTPS response has no Content-Security-Policy header. Without CSP, browsers allow inline scripts and broad resource loads, which increases impact if an XSS or injection bug exists.",
			Evidence: ev,
			Remediation: "Send a strict CSP on every HTML response, e.g. default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. Start with Content-Security-Policy-Report-Only to test, then enforce.",
			ReferenceURL: mdnHeader("Content-Security-Policy"),
		}
	case "X-Content-Type-Options":
		return model.Finding{
			Code: "HTTP-015", Severity: model.SeverityLow,
			Title: `X-Content-Type-Options not "nosniff"`,
			Description: "This header should be exactly \"nosniff\" so browsers do not MIME-sniff responses away from the declared Content-Type (reduces some XSS/upload risks).",
			Evidence: ev,
			Remediation: "Set header: X-Content-Type-Options: nosniff on all responses (especially HTML, JSON, and downloads).",
			ReferenceURL: mdnHeader("X-Content-Type-Options"),
		}
	case "Referrer-Policy":
		return model.Finding{
			Code: "HTTP-015", Severity: model.SeverityLow,
			Title: "Referrer-Policy missing",
			Description: "No Referrer-Policy was sent. Cross-origin navigations may leak full URLs (including query strings) to third parties via the Referer header.",
			Evidence: ev,
			Remediation: "Set e.g. Referrer-Policy: strict-origin-when-cross-origin or no-referrer-when-downgrade on HTML responses.",
			ReferenceURL: mdnHeader("Referrer-Policy"),
		}
	case "X-XSS-Protection":
		return model.Finding{
			Code: "HTTP-015", Severity: model.SeverityLow,
			Title: "Legacy X-XSS-Protection header enabled",
			Description: "X-XSS-Protection is deprecated and can introduce quirks in some browsers. Modern mitigation is CSP, not this header.",
			Evidence: ev,
			Remediation: "Remove X-XSS-Protection (or set to 0) and rely on Content-Security-Policy instead.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection",
		}
	case "Public-Key-Pins", "Public-Key-Pins-Report-Only":
		return model.Finding{
			Code: "HTTP-015", Severity: model.SeverityMedium,
			Title: hi.Header + " present (deprecated HPKP)",
			Description: "HTTP Public Key Pinning (HPKP) is deprecated and was removed from browsers. Keeping these headers adds no security and may confuse operators.",
			Evidence: ev,
			Remediation: "Remove Public-Key-Pins and Public-Key-Pins-Report-Only headers. Use certificate monitoring and short-lived certs / automation instead.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Public-Key-Pins",
		}
	default:
		return model.Finding{
			Code: "HTTP-015", Severity: model.SeverityLow,
			Title: fmt.Sprintf("HTTP header issue: %s", hi.Header),
			Description: "A recommended security-related response header is missing or misconfigured.",
			Evidence: ev,
			Remediation: "Review this header in your web server or app framework configuration.",
		}
	}
}
