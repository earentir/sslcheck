package report

import (
	"fmt"
	"sort"
	"strings"
)

// CheckDefinition describes a supported finding/check code (catalog entry).
type CheckDefinition struct {
	Code         string `json:"code"`
	Category     string `json:"category"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
	Remediation  string `json:"remediation,omitempty"`
	ReferenceURL string `json:"reference_url,omitempty"`
}

// checkSummary is the list-view shape for GET /api/v1/checks.
type checkSummary struct {
	Code     string `json:"code"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

// ChecksListResponse is returned by GET /api/v1/checks.
type ChecksListResponse struct {
	Checks []checkSummary `json:"checks"`
	Count  int            `json:"count"`
}

var catalog = []CheckDefinition{
	// CERT
	{Code: "CERT-001", Category: "CERT", Severity: "critical", Title: "No certificate presented",
		Description: "Handshake succeeded but no peer certificate chain was returned—invalid for HTTPS.",
		Remediation: "Configure the TLS listener to send the server certificate chain.",
		ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
	{Code: "CERT-010", Category: "CERT", Severity: "critical", Title: "Certificate not yet valid",
		Description: "Current time is before NotBefore—clients will reject until that instant.",
		Remediation: "Deploy a cert already in validity, or fix server clock skew.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-011", Category: "CERT", Severity: "critical", Title: "Certificate expired",
		Description: "NotAfter is in the past—browsers show certificate errors.",
		Remediation: "Issue a new cert and reload TLS; automate renewal (ACME etc.).",
		ReferenceURL: "https://letsencrypt.org/getting-started/"},
	{Code: "CERT-012", Category: "CERT", Severity: "medium", Title: "Certificate expires soon",
		Description: "Less than 8 days until NotAfter.",
		Remediation: "Renew now; shorten renewal automation window if this is recurring.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/"},
	{Code: "CERT-013", Category: "CERT", Severity: "medium", Title: "Certificate expiry approaching",
		Description: "30 days or fewer remaining—plan renewal before busy period.",
		Remediation: "Schedule renewal and test staging deploy.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/"},
	{Code: "CERT-020", Category: "CERT", Severity: "critical", Title: "Certificate hostname mismatch",
		Description: "Requested name is not in leaf SAN/CN per hostname verification.",
		Remediation: "Reissue with SAN covering this exact hostname (and www if needed).",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-021", Category: "CERT", Severity: "critical", Title: "Certificate chain is not trusted",
		Description: "System roots + presented intermediates could not build a path to a trusted anchor.",
		Remediation: "Install missing intermediate(s) on the server; avoid self-signed for public sites.",
		ReferenceURL: "https://wiki.mozilla.org/CA/Included_Certificates"},
	{Code: "CERT-030", Category: "CERT", Severity: "high", Title: "Weak certificate signature algorithm",
		Description: "Leaf uses a legacy signature algorithm (e.g. SHA-1).",
		Remediation: "Reissue with SHA-256 or stronger signature.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-031", Category: "CERT", Severity: "high", Title: "Weak RSA key size",
		Description: "RSA public key is below 2048 bits.",
		Remediation: "Reissue with RSA 2048+ or prefer ECDSA/Ed25519.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-032", Category: "CERT", Severity: "info", Title: "RSA key size acceptable but not strong",
		Description: "RSA 2048 is acceptable but 3072/4096 or ECDSA is preferred for long-lived certs.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-033", Category: "CERT", Severity: "high", Title: "Weak ECDSA curve",
		Description: "ECDSA key uses a weak or non-standard curve.",
		Remediation: "Reissue with P-256, P-384, or P-521.",
		ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8422"},
	{Code: "CERT-034", Category: "CERT", Severity: "info", Title: "Unexpected public key type",
		Description: "Public key algorithm is not RSA/ECDSA/Ed25519 in usual paths.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-040", Category: "CERT", Severity: "info", Title: "No SCTs observed",
		Description: "No embedded SCTs in cert/handshake—CT may still be satisfied via logs or OCSP stapling.",
		ReferenceURL: "https://certificate.transparency.dev/"},
	{Code: "CERT-041", Category: "CERT", Severity: "info", Title: "No OCSP responder URI",
		Description: "Leaf certificate has no Authority Information Access OCSP URL.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "CERT-042", Category: "CERT", Severity: "info", Title: "No CRL distribution points",
		Description: "Leaf certificate has no CRLDistributionPoints extension.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3"},
	{Code: "CERT-043", Category: "CERT", Severity: "info", Title: "SCTs present (embedded extension)",
		Description: "Certificate carries CT extension; handshake SCT count was zero.",
		ReferenceURL: "https://certificate.transparency.dev/"},
	{Code: "CERT-050", Category: "CERT", Severity: "high", Title: "Leaf certificate marked as CA",
		Description: "BasicConstraints CA=true on the server leaf is wrong for TLS web server certs.",
		Remediation: "Use an end-entity (EE) server certificate from your CA.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-051", Category: "CERT", Severity: "medium", Title: "Invalid basic constraints",
		Description: "Leaf basicConstraints extension missing or malformed.",
		Remediation: "Reissue certificate with valid Basic Constraints (CA:false for EE).",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9"},
	{Code: "CERT-052", Category: "CERT", Severity: "medium", Title: "No intermediates presented",
		Description: "Server sent only the leaf in TLS—clients may fail if they lack the intermediate.",
		Remediation: "Concatenate full chain (leaf + intermediate(s)) in server config.",
		ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
	{Code: "CERT-053", Category: "CERT", Severity: "high", Title: "Non-CA certificate in chain",
		Description: "A certificate in the middle of the chain is not marked CA—path is invalid.",
		Remediation: "Reorder or replace chain so only CA certs appear between leaf and root.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-6.1"},
	{Code: "CERT-054", Category: "CERT", Severity: "critical", Title: "Expired intermediate in chain",
		Description: "An intermediate certificate in the built chain is past NotAfter.",
		Remediation: "Replace intermediate or update server chain.",
		ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
	{Code: "CERT-055", Category: "CERT", Severity: "medium", Title: "SHA-1 signed intermediate",
		Description: "Intermediate uses SHA-1 signature algorithm.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-056", Category: "CERT", Severity: "medium", Title: "Weak RSA intermediate key",
		Description: "Intermediate RSA key is below 2048 bits.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-057", Category: "CERT", Severity: "info", Title: "Short-lived certificate",
		Description: "Leaf validity is under 15 days—ensure automated renewal (ACME) is in place.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/"},
	{Code: "CERT-060", Category: "CERT", Severity: "high", Title: "Extended key usage includes any",
		Description: "EKU anyExtendedKeyUsage on a TLS server cert is overly broad.",
		Remediation: "Reissue with extKeyUsage serverAuth only.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12"},
	{Code: "CERT-061", Category: "CERT", Severity: "high", Title: "Missing serverAuth extended key usage",
		Description: "Leaf EKU does not include id-kp-serverAuth.",
		Remediation: "Use a certificate with serverAuth EKU for HTTPS.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12"},
	{Code: "CERT-062", Category: "CERT", Severity: "medium", Title: "Encipherment-only key usage",
		Description: "Leaf keyUsage is encipherment without digitalSignature—unusual for modern TLS server certs.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3"},
	{Code: "CERT-063", Category: "CERT", Severity: "medium", Title: "Multiple wildcards in SAN",
		Description: "Certificate SAN contains more than one wildcard label.",
		ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	{Code: "CERT-064", Category: "CERT", Severity: "low", Title: "Wildcard SAN may not cover requested host",
		Description: "Requested hostname may not match wildcard SAN depth rules.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6125"},

	// DNS
	{Code: "DNS-001", Category: "DNS", Severity: "critical", Title: "DNS resolution failed",
		Description: "Resolver could not resolve the hostname—no usable A/AAAA answers.",
		Remediation: "Create A/AAAA records at your DNS provider; confirm propagation.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/Domain_name"},
	{Code: "DNS-002", Category: "DNS", Severity: "critical", Title: "No A/AAAA records",
		Description: "Lookup succeeded but produced no IPv4 or IPv6 addresses.",
		Remediation: "Add at least one A (IPv4) or AAAA (IPv6) record pointing to your origin.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/Domain_name"},
	{Code: "DNS-003", Category: "DNS", Severity: "info", Title: "Multiple IPs detected",
		Description: "Several addresses are published; the scanner probes each and compares TLS behavior.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/Load_balancer"},
	{Code: "DNS-010", Category: "DNS", Severity: "info", Title: "No CAA records found",
		Description: "CAA limits which CAs may issue certs; absence means any CA could issue if they validate control.",
		Remediation: "Publish CAA at DNS e.g. 0 issue \"letsencrypt.org\" for your zone.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659"},
	{Code: "DNS-011", Category: "DNS", Severity: "info", Title: "CAA records found",
		Description: "Certificate Authority Authorization records published for this name.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659"},
	{Code: "DNS-012", Category: "DNS", Severity: "high", Title: "CAA policy does not authorize observed issuer",
		Description: "CAA records exist but do not authorize the certificate issuer presented during TLS.",
		Remediation: "Update CAA at DNS to include the issuing CA, or obtain a cert from an authorized CA.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659"},
	{Code: "DNS-020", Category: "DNS", Severity: "info", Title: "Dual-stack DNS detected",
		Description: "Both A and AAAA records are published for this name.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/IPv6"},
	{Code: "DNS-021", Category: "DNS", Severity: "info", Title: "IPv6-only DNS detected",
		Description: "Only AAAA records returned—IPv4-only clients cannot connect.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/IPv6"},
	{Code: "DNS-022", Category: "DNS", Severity: "info", Title: "IPv4-only DNS detected",
		Description: "No AAAA records—IPv6-only clients cannot connect.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/IPv6"},
	{Code: "DNS-030", Category: "DNS", Severity: "medium", Title: "TLSA records present but cert digest unavailable",
		Description: "TLSA RRSET exists but the scanner could not compare presented certificate data.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6698"},
	{Code: "DNS-031", Category: "DNS", Severity: "info", Title: "TLSA matches presented certificate",
		Description: "At least one TLSA record matches the observed certificate data.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6698"},
	{Code: "DNS-032", Category: "DNS", Severity: "high", Title: "TLSA policy mismatch",
		Description: "TLSA records exist but none match the certificate presented during TLS.",
		Remediation: "Update TLSA at DNS or deploy the certificate matching published TLSA.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6698"},

	// EDGE
	{Code: "EDGE-001", Category: "EDGE", Severity: "medium", Title: "TLS version inconsistency across IPs",
		Description: "Same hostname resolves to multiple IPs but TLS max negotiated version is not uniform.",
		Remediation: "Apply one TLS policy on all LBs and origins (same min/max protocol).",
		ReferenceURL: "https://ssl-config.mozilla.org/"},
	{Code: "EDGE-002", Category: "EDGE", Severity: "low", Title: "Cipher suite inconsistency across IPs",
		Description: "Different backends negotiated different ciphers.",
		Remediation: "Standardize cipher suite order and allowed list everywhere.",
		ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
	{Code: "EDGE-003", Category: "EDGE", Severity: "high", Title: "Certificate inconsistency across IPs",
		Description: "At least two distinct leaf certs across A/AAAA targets.",
		Remediation: "Deploy identical chain to all nodes or document intentional split with valid SANs.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/"},
	{Code: "EDGE-004", Category: "EDGE", Severity: "high", Title: "IPv4 vs IPv6 leaf certificate mismatch",
		Description: "TLS succeeded on both families but presented leaf certificates differ.",
		Remediation: "Serve the same certificate (and chain) on all published addresses.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/"},
	{Code: "EDGE-005", Category: "EDGE", Severity: "medium", Title: "Different public keys across IPs",
		Description: "Same hostname resolves to multiple IPs but TLS endpoints present different SPKI fingerprints.",
		Remediation: "Serve the same certificate/key on all published addresses unless split is intentional.",
		ReferenceURL: "https://letsencrypt.org/docs/integration-guide/"},

	// HTTP
	{Code: "HTTP-001", Category: "HTTP", Severity: "medium", Title: "HTTP redirect check failed",
		Description: "Could not complete HTTP (port 80) redirect probe.",
		Remediation: "Ensure port 80 responds and redirects to HTTPS if required."},
	{Code: "HTTP-002", Category: "HTTP", Severity: "high", Title: "HTTP does not clearly redirect to HTTPS",
		Description: "Port 80 response did not redirect to HTTPS.",
		Remediation: "Configure HTTP→HTTPS redirect on port 80."},
	{Code: "HTTP-003", Category: "HTTP", Severity: "info", Title: "HTTP redirects to HTTPS",
		Description: "Port 80 redirects clients to HTTPS."},
	{Code: "HTTP-004", Category: "HTTP", Severity: "low", Title: "Redirect chain inspection failed",
		Description: "Could not fully walk the HTTP redirect chain."},
	{Code: "HTTP-005", Category: "HTTP", Severity: "high", Title: "Redirect chain downgraded to HTTP",
		Description: "Redirect chain used HTTP after an earlier HTTPS hop.",
		Remediation: "Ensure all redirects stay on HTTPS."},
	{Code: "HTTP-006", Category: "HTTP", Severity: "low", Title: "Long redirect chain",
		Description: "Many redirect hops before final URL."},
	{Code: "HTTP-007", Category: "HTTP", Severity: "info", Title: "Redirect changed hostname",
		Description: "Redirect chain changed hostname (may be intentional)."},
	{Code: "HTTP-010", Category: "HTTP", Severity: "medium", Title: "HTTPS fetch failed",
		Description: "HTTPS GET to the target URL failed.",
		Remediation: "Verify TLS, DNS, and HTTP service on 443."},
	{Code: "HTTP-011", Category: "HTTP", Severity: "medium", Title: "HSTS header missing",
		Description: "Strict-Transport-Security header not present on HTTPS response.",
		Remediation: "Add HSTS with appropriate max-age (≥1 year recommended).",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
	{Code: "HTTP-012", Category: "HTTP", Severity: "medium", Title: "HSTS disabled or low",
		Description: "HSTS max-age is zero or below recommended one-year minimum.",
		Remediation: "Set max-age to at least 31536000 (1 year) if HSTS is intended.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
	{Code: "HTTP-013", Category: "HTTP", Severity: "info", Title: "HSTS does not include subdomains",
		Description: "HSTS header lacks includeSubDomains directive.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
	{Code: "HTTP-015", Category: "HTTP", Severity: "medium", Title: "HTTP security header issue",
		Description: "Missing or weak security header (CSP, X-Frame-Options, X-Content-Type-Options, etc.).",
		ReferenceURL: "https://owasp.org/www-project-secure-headers/"},
	{Code: "HTTP-020", Category: "HTTP", Severity: "medium", Title: "Cookie security flags are incomplete",
		Description: "Set-Cookie missing Secure, HttpOnly, or SameSite as appropriate.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"},
	{Code: "HTTP-030", Category: "HTTP", Severity: "high", Title: "Possible mixed content detected",
		Description: "HTML references active HTTP or WS subresources on an HTTPS page.",
		Remediation: "Upgrade subresource URLs to HTTPS or use relative/protocol-relative URLs.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"},
	{Code: "HTTP-031", Category: "HTTP", Severity: "high", Title: "Active HTTPS subresource host has TLS errors",
		Description: "A subresource hostname referenced over HTTPS failed TLS checks.",
		Remediation: "Fix TLS on subresource hosts or remove broken references."},
	{Code: "HTTP-040", Category: "HTTP", Severity: "info", Title: "HTTP/3 advertised",
		Description: "Alt-Svc header advertises HTTP/3 (QUIC).",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Svc"},

	// NET
	{Code: "NET-001", Category: "NET", Severity: "high", Title: "TCP connection failed",
		Description: "Could not open a TCP connection to IP:port (refused, timeout, or reset).",
		Remediation: "Listen on 443; allow inbound TCP in firewall/security group.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"},
	{Code: "NET-002", Category: "NET", Severity: "info", Title: "Address family unreachable from scanner (routing)",
		Description: "TCP dial failed with a routing error on the scanner (e.g. no route to host)—not proof the server is down.",
		Remediation: "Compare the other address family if listed.",
		ReferenceURL: "https://en.wikipedia.org/wiki/IPv6#Deployment"},

	// POL
	{Code: "POL-001", Category: "POL", Severity: "low", Title: "Profile requires CAA",
		Description: "Strict profile expects CAA records so only approved CAs can issue certs for this zone.",
		Remediation: "Add CAA at DNS for the hostname and parent zone as needed.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659"},
	{Code: "POL-003", Category: "POL", Severity: "high", Title: "Strict profile: CAA does not authorize issuer",
		Description: "Strict profile requires CAA to allow the observed certificate issuer.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659"},
	{Code: "POL-004", Category: "POL", Severity: "critical", Title: "Strict profile: Must-Staple not satisfied",
		Description: "Certificate requires OCSP Must-Staple but stapling is missing or not good.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc7633"},
	{Code: "POL-005", Category: "POL", Severity: "medium", Title: "Strict profile: no CT/SCT evidence",
		Description: "Strict profile expects certificate transparency signals (embedded SCT or handshake SCTs).",
		ReferenceURL: "https://certificate.transparency.dev/"},
	{Code: "POL-006", Category: "POL", Severity: "low", Title: "Strict profile: no CRL distribution points",
		Description: "Strict profile expects CRL URLs on the leaf for offline revocation checking.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3"},

	// TLS
	{Code: "TLS-001", Category: "TLS", Severity: "critical", Title: "TLS handshake failed",
		Description: "Could not complete TLS after TCP connected—wrong cert/SNI, TLS disabled, or cipher/protocol mismatch.",
		Remediation: "Enable TLS on 443, set correct SNI vhost, allow TLS 1.2+, present valid chain.",
		ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
	{Code: "TLS-010", Category: "TLS", Severity: "critical", Title: "Legacy TLS negotiated",
		Description: "Best handshake used TLS 1.0 or 1.1, which are deprecated and unsafe for HTTPS.",
		Remediation: "Set minimum TLS to 1.2 (prefer 1.3). Remove TLS 1.0/1.1 everywhere.",
		ReferenceURL: "https://ssl-config.mozilla.org/"},
	{Code: "TLS-011", Category: "TLS", Severity: "critical", Title: "Legacy TLS version supported",
		Description: "Dedicated probe confirmed handshakes still complete on TLS 1.0/1.1.",
		Remediation: "Disable TLS 1.0 and 1.1 everywhere (LB + origin).",
		ReferenceURL: "https://ssl-config.mozilla.org/"},
	{Code: "TLS-012", Category: "TLS", Severity: "critical", Title: "No modern TLS support",
		Description: "Neither TLS 1.2 nor 1.3 completed in version probes.",
		Remediation: "Enable TLS 1.2 minimum; add TLS 1.3 where possible.",
		ReferenceURL: "https://ssl-config.mozilla.org/"},
	{Code: "TLS-020", Category: "TLS", Severity: "info", Title: "No ALPN negotiated",
		Description: "ALPN was empty after handshake—HTTP/2 over TLS usually needs h2 in ALPN.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/ALPN"},
	{Code: "TLS-021", Category: "TLS", Severity: "info", Title: "OCSP stapling not offered",
		Description: "Leaf cert lists an OCSP URL but handshake had no stapled OCSP response.",
		Remediation: "Enable OCSP stapling in your web server.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#ocsp_stapling"},
	{Code: "TLS-022", Category: "TLS", Severity: "info", Title: "HTTP/2 ALPN not negotiated",
		Description: "Server did not select h2 when only h2 was offered.",
		Remediation: "Enable HTTP/2 (and ALPN h2) if you want H2 on this endpoint.",
		ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/HTTP_2"},
	{Code: "TLS-030", Category: "TLS", Severity: "info", Title: "Handshake without SNI succeeded",
		Description: "ClientHello had no ServerName; server still answered with a default cert.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3"},
	{Code: "TLS-031", Category: "TLS", Severity: "info", Title: "Wrong-SNI handshake rejected",
		Description: "Server rejected TLS when SNI did not match the probed hostname.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3"},
	{Code: "TLS-032", Category: "TLS", Severity: "info", Title: "Wrong-SNI handshake still returned matching certificate",
		Description: "Wrong SNI was accepted but returned the same cert as the real hostname.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3"},
	{Code: "TLS-033", Category: "TLS", Severity: "info", Title: "Wrong-SNI handshake returned different certificate",
		Description: "Wrong SNI returned a different certificate (default vhost behavior).",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3"},
	{Code: "TLS-050", Category: "TLS", Severity: "high", Title: "Weak TLS cipher accepted",
		Description: "Server completed TLS 1.2 with a legacy weak cipher (3DES, RSA key exchange, CBC).",
		Remediation: "Remove 3DES, RSA key exchange, and CBC ciphers; keep ECDHE+AEAD.",
		ReferenceURL: "https://ssl-config.mozilla.org/"},
	{Code: "TLS-051", Category: "TLS", Severity: "critical", Title: "Insecure TLS cipher accepted",
		Description: "Server accepted a cipher classified as insecure (NULL, export, or anon).",
		Remediation: "Disable all NULL, export, and anonymous cipher suites.",
		ReferenceURL: "https://ssl-config.mozilla.org/"},
	{Code: "TLS-060", Category: "TLS", Severity: "info", Title: "TLS 1.2 session resumption not observed",
		Description: "Second handshake did not show TLS 1.2 resumption.",
		ReferenceURL: "https://wiki.openssl.org/index.php/TLS1.3#Session_Resumption"},
	{Code: "TLS-061", Category: "TLS", Severity: "info", Title: "TLS 1.3 session resumption not observed",
		Description: "TLS 1.3 PSK/ticket resumption was not observed on retry.",
		ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8446#section-2.2"},
	{Code: "TLS-070", Category: "TLS", Severity: "info", Title: "Supported key exchange group observed",
		Description: "Informational: server negotiated a supported key exchange group during probe.",
		ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7"},
	{Code: "TLS-080", Category: "TLS", Severity: "low", Title: "OCSP responder unreachable",
		Description: "Active check: POST to the cert's OCSP URL failed from the scanner.",
		Remediation: "Ensure OCSP URLs are reachable; prefer stapling.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "TLS-081", Category: "TLS", Severity: "low", Title: "OCSP responder returned unparseable response",
		Description: "HTTP reply was not a valid OCSP response for this cert/issuer.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "TLS-082", Category: "TLS", Severity: "critical", Title: "OCSP responder reports certificate revoked",
		Description: "Live OCSP query returned revoked.",
		Remediation: "Stop using this certificate; investigate compromise or CA revocation reason.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "TLS-083", Category: "TLS", Severity: "medium", Title: "OCSP responder returned unknown status",
		Description: "Responder could not return good/revoked for this serial.",
		Remediation: "Contact CA; reissue cert if unknown persists.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "TLS-085", Category: "TLS", Severity: "critical", Title: "Must-Staple required but stapling missing or invalid",
		Description: "Certificate carries OCSP Must-Staple but handshake did not include a good stapled OCSP response.",
		Remediation: "Enable OCSP stapling on the server or remove Must-Staple from the certificate.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc7633"},
	{Code: "TLS-086", Category: "TLS", Severity: "critical", Title: "Stapled OCSP: certificate revoked",
		Description: "The stapled OCSP response indicates the certificate is revoked.",
		Remediation: "Stop using this certificate immediately.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "TLS-087", Category: "TLS", Severity: "high", Title: "Stapled OCSP status not good",
		Description: "Stapled OCSP response could not be validated as good (unknown or parse error).",
		Remediation: "Fix stapling configuration or reissue certificate.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960"},
	{Code: "TLS-088", Category: "TLS", Severity: "critical", Title: "CRL: certificate revoked",
		Description: "Fetched CRL lists this certificate serial as revoked.",
		Remediation: "Stop using this certificate.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3"},
	{Code: "TLS-089", Category: "TLS", Severity: "low", Title: "CRL fetch failed",
		Description: "Could not fetch or parse any CRL from distribution points.",
		Remediation: "Ensure CRL URLs are reachable; prefer OCSP stapling where possible."},
	{Code: "TLS-090", Category: "TLS", Severity: "info", Title: "Server cipher preference observed",
		Description: "Server picks cipher order (not client)—ensure server list prioritizes AEAD.",
		ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
	{Code: "TLS-091", Category: "TLS", Severity: "low", Title: "TLS fallback SCSV not enforced",
		Description: "Server did not reject a TLS 1.0 fallback attempt with TLS_FALLBACK_SCSV.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc7507"},
}

var catalogByCode map[string]CheckDefinition

func init() {
	catalogByCode = make(map[string]CheckDefinition, len(catalog))
	AllCodes = make(map[string]string, len(catalog))
	for _, c := range catalog {
		catalogByCode[c.Code] = c
		AllCodes[c.Code] = c.Title
	}
}

// ListChecks returns all supported finding codes (sorted by code).
func ListChecks() ChecksListResponse {
	out := make([]checkSummary, 0, len(catalog))
	for _, c := range catalog {
		out = append(out, checkSummary{
			Code: c.Code, Category: c.Category, Title: c.Title, Severity: c.Severity,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return ChecksListResponse{Checks: out, Count: len(out)}
}

// GetCheck returns the catalog entry for code, or false if unknown.
func GetCheck(code string) (CheckDefinition, bool) {
	code = NormalizeCheckCode(code)
	c, ok := catalogByCode[code]
	return c, ok
}

// NormalizeCheckCode uppercases and trims a finding code (e.g. cert-011 → CERT-011).
func NormalizeCheckCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// ValidateCheckCode reports whether code looks like a supported finding ID format.
func ValidateCheckCode(code string) error {
	code = NormalizeCheckCode(code)
	if code == "" {
		return fmt.Errorf("code is required")
	}
	if !strings.Contains(code, "-") {
		return fmt.Errorf("code must look like CERT-011")
	}
	return nil
}
