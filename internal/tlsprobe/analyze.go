package tlsprobe

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"sslcheck/internal/model"
)

// AnalyzeEndpoint turns agent-collected probe data into a full EndpointResult with findings.
func AnalyzeEndpoint(cap model.EndpointCapture, host string, opts Options) model.EndpointResult {
	result := model.EndpointResult{
		IP: cap.IP, Network: cap.Network,
		TCPReachable: cap.TCPReachable, TCPConnectLatency: cap.TCPConnectLatency,
		ProtocolSupport: cap.ProtocolSupport, WeakCipherSupport: cap.WeakCipherSupport,
		ALPNProbe: cap.ALPNProbe, Resumption: cap.Resumption, CipherPreference: cap.CipherPreference,
		TLSErrorNoSNI: cap.TLSErrorNoSNI, NoSNIHandshakeOK: cap.NoSNIHandshakeOK,
		NoSNICertCN: cap.NoSNICertCN, NoSNICertSANs: cap.NoSNICertSANs,
		Errors: append([]string(nil), cap.Errors...), Warnings: append([]string(nil), cap.Warnings...),
	}
	if cap.ProtocolSupport == nil {
		result.ProtocolSupport = make(map[string]bool)
	}
	if cap.WeakCipherSupport == nil {
		result.WeakCipherSupport = []string{}
	}

	if cap.TCPDialErr != "" {
		result.Errors = append(result.Errors, "tcp connect failed: "+cap.TCPDialErr)
		result.Findings = append(result.Findings, tcpDialFinding(cap.Network, cap.IP, fmt.Errorf("%s", cap.TCPDialErr)))
		model.SortFindings(result.Findings)
		return result
	}

	if cap.HandshakeErr != "" {
		result.Errors = append(result.Errors, "tls handshake failed: "+cap.HandshakeErr)
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-001", Severity: model.SeverityCritical, Title: "TLS handshake failed",
			Description: "Could not complete TLS with this IP after TCP connected—often wrong cert/SNI, TLS disabled on this vhost, or cipher/protocol mismatch.",
			Evidence:    fmt.Sprintf("IP %s, SNI %q, error: %s", cap.IP, host, cap.HandshakeErr),
			Remediation: "On the server: enable TLS on 443, set correct ServerName/SNI vhost, allow TLS 1.2+, and present a valid chain for this hostname.",
			ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
		})
		if cap.NoSNIHandshakeOK {
			result.Findings = append(result.Findings, noSNIFinding(cap.IP, cap.NoSNICertCN, cap.NoSNICertSANs))
		}
		model.SortFindings(result.Findings)
		return result
	}

	if !cap.TLSHandshakeOK {
		model.SortFindings(result.Findings)
		return result
	}

	rawChain := certsFromDER(cap.PeerCertsDER)
	fullChain := certsFromDER(cap.FullChainDER)
	if len(fullChain) == 0 {
		fullChain = rawChain
	}

	result.TLSHandshakeOK = true
	result.TLSVersion = cap.TLSVersion
	result.CipherSuite = cap.CipherSuite
	result.ServerName = cap.ServerName
	result.ALPN = cap.ALPN
	result.PeerCertCount = cap.PeerCertCount
	result.OCSPStapled = len(cap.OCSPStapledResponse) > 0
	result.SCTCount = cap.SCTCount

	bestState := tls.ConnectionState{
		Version:                     cap.TLSVersionID,
		CipherSuite:                 cap.CipherSuiteID,
		ServerName:                  cap.ServerName,
		NegotiatedProtocol:          cap.ALPN,
		PeerCertificates:            rawChain,
		OCSPResponse:                cap.OCSPStapledResponse,
		SignedCertificateTimestamps: make([][]byte, cap.SCTCount),
	}

	analyzeCapturedHandshake(&result, host, cap.IP, bestState, rawChain, fullChain, cap, opts)
	result.Findings = append(result.Findings, networkProbeFindings(host, cap)...)
	appendPostHandshakeFindings(&result, host, cap.IP, bestState)
	model.SortFindings(result.Findings)
	return result
}

func analyzeCapturedHandshake(result *model.EndpointResult, host, ip string, bestState tls.ConnectionState, rawChain, fullChain []*x509.Certificate, cap model.EndpointCapture, opts Options) {
	stapleStatus := ""
	if result.OCSPStapled {
		if status, err := parseOCSPStatus(bestState.OCSPResponse, rawChain); err == nil {
			result.OCSPStatus = status
			result.OCSPStapledStatus = status
			stapleStatus = status
		} else {
			result.OCSPStapledStatus = "parse_error"
			stapleStatus = "parse_error"
			result.Warnings = append(result.Warnings, "ocsp stapling present but parse failed: "+err.Error())
		}
	} else {
		result.OCSPStapledStatus = "none"
	}
	if !result.OCSPStapled && summaryChainHasOCSP(rawChain) {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-021", Severity: model.SeverityInfo, Title: "OCSP stapling not offered",
			Description: "The leaf cert lists an OCSP URL, but the TLS handshake had no stapled OCSP response—clients must query the CA instead.",
			Evidence:    fmt.Sprintf("IP %s · OCSP URLs on cert: %s", ip, strings.Join(rawChain[0].OCSPServer, ", ")),
			Remediation: "Enable OCSP stapling in your web server (e.g. nginx ssl_stapling, Apache SSLUseStapling).",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#ocsp_stapling",
		})
	}

	summary, certFindings := analyzeCertificates(host, fullChain)
	result.CertSummary = summary
	result.Findings = append(result.Findings, certFindings...)
	result.Findings = append(result.Findings, lintChain(fullChain, len(rawChain))...)
	result.CertificateChainDetails = buildChainCertificateDetails(fullChain, rawChain, cap.ChainFetchedFP)
	result.ChainBuildNotes = append([]string(nil), cap.ChainBuildNotes...)
	if !cap.ChainVerifiedOK && len(fullChain) > 0 {
		result.ChainBuildNotes = append(result.ChainBuildNotes,
			"Chain not fully verified to a system trust anchor with the built path (see certificate findings).")
	}
	result.CertificateTransparency = BuildCTSummary(bestState, fullChain)
	result.Findings = append(result.Findings, ctFindings(result.CertificateTransparency, ip)...)

	activeFindings := activeOCSPFindingsFromCapture(cap.ActiveOCSP)
	if !opts.SkipActiveOCSP {
		result.Findings = append(result.Findings, activeFindings...)
	}
	crlFinding, crlStatus := crlFindingFromCapture(cap)
	if crlFinding.Code != "" {
		result.Findings = append(result.Findings, crlFinding)
	}
	if crlStatus == "" {
		crlStatus = cap.CRLStatus
	}
	crlChecked := cap.CRLChecked || crlStatus == "good" || crlStatus == "revoked"
	if len(fullChain) > 0 {
		result.Revocation = buildRevocationSummary(fullChain[0], result.OCSPStapled, stapleStatus, activeFindings, crlChecked, crlStatus, !opts.SkipActiveOCSP)
		if hasMustStaple(fullChain[0]) {
			result.Findings = append(result.Findings, mustStapleFindings(result.OCSPStapled, stapleStatus, ip)...)
		}
		if result.OCSPStapled {
			result.Findings = append(result.Findings, stapledOCSPFindings(stapleStatus, ip)...)
		}
		result.Findings = append(result.Findings, certQualityFindings(fullChain, host, ip)...)
	}
}

func activeOCSPFindingsFromCapture(caps []model.ActiveOCSPCapture) []model.Finding {
	var findings []model.Finding
	for _, c := range caps {
		if c.FetchErr != "" {
			findings = append(findings, model.Finding{
				Code: "TLS-080", Severity: model.SeverityLow, Title: "OCSP responder unreachable",
				Description: "Active check: POST to the cert’s OCSP URL failed from the scanner (network, firewall, or downtime).",
				Evidence:    fmt.Sprintf("%s: %s", c.URL, c.FetchErr),
				Remediation: "Ensure OCSP URLs are reachable; prefer stapling to reduce client dependency on responder uptime.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
			continue
		}
		if c.ParseErr != "" {
			findings = append(findings, model.Finding{
				Code: "TLS-081", Severity: model.SeverityLow, Title: "OCSP response unparseable",
				Description: "HTTP reply was not a valid OCSP response for this cert/issuer (wrong MIME, proxy HTML, truncated body).",
				Evidence:    fmt.Sprintf("%s parse error: %s", c.URL, c.ParseErr),
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
			continue
		}
		switch c.Status {
		case "revoked":
			findings = append(findings, model.Finding{
				Code: "TLS-082", Severity: model.SeverityCritical, Title: "OCSP: certificate revoked",
				Description: "Live OCSP query returned revoked—browsers that check OCSP should reject this cert.",
				Evidence: c.URL,
				Remediation: "Stop using this certificate; investigate compromise or CA revocation reason.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
		case "unknown":
			findings = append(findings, model.Finding{
				Code: "TLS-083", Severity: model.SeverityMedium, Title: "OCSP: unknown status",
				Description: "Responder could not return good/revoked for this serial—may indicate mis-issued cert or CA issue.",
				Evidence: c.URL,
				Remediation: "Contact CA; reissue cert if unknown persists.",
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
			})
		}
	}
	return findings
}

func crlFindingFromCapture(cap model.EndpointCapture) (model.Finding, string) {
	status := cap.CRLStatus
	if status == "revoked" {
		return model.Finding{
			Code: "TLS-088", Severity: model.SeverityCritical, Title: "CRL: certificate revoked",
			Description: "Fetched CRL lists this certificate serial as revoked.",
			Evidence: "CRL from collect",
			Remediation: "Stop using this certificate.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3",
		}, status
	}
	if status == "good" {
		return model.Finding{}, status
	}
	if cap.CRLFetchErr != "" || status == "unreachable" {
		return model.Finding{
			Code: "TLS-089", Severity: model.SeverityLow, Title: "CRL fetch failed",
			Description: "Could not fetch or parse any CRL from distribution points.",
			Evidence: cap.CRLFetchErr,
			Remediation: "Ensure CRL URLs are reachable; prefer OCSP stapling where possible.",
		}, "unreachable"
	}
	return model.Finding{}, status
}

func networkProbeFindings(host string, cap model.EndpointCapture) []model.Finding {
	var findings []model.Finding
	ip := cap.IP
	for name, supported := range cap.ProtocolSupport {
		if (name == "TLS1.0" || name == "TLS1.1") && supported {
			findings = append(findings, model.Finding{
				Code: "TLS-011", Severity: model.SeverityCritical, Title: "Legacy TLS version supported",
				Description: "A separate probe confirmed this IP still completes handshakes on TLS 1.0/1.1—downgrade attacks become possible.",
				Evidence:    fmt.Sprintf("IP %s accepts %s (dedicated version probe)", ip, name),
				Remediation: "Disable TLS 1.0 and 1.1 everywhere (LB + origin).",
				ReferenceURL: "https://ssl-config.mozilla.org/",
			})
		}
	}
	if cap.ProtocolSupport != nil && !cap.ProtocolSupport["TLS1.2"] && !cap.ProtocolSupport["TLS1.3"] {
		findings = append(findings, model.Finding{
			Code: "TLS-012", Severity: model.SeverityCritical, Title: "No modern TLS support",
			Description: "Neither TLS 1.2 nor 1.3 completed in our version probes—browsers will fail or use only legacy TLS.",
			Evidence:    fmt.Sprintf("IP %s protocol map: %+v", ip, cap.ProtocolSupport),
			Remediation: "Enable TLS 1.2 minimum; add TLS 1.3 where possible.",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
	for _, name := range cap.WeakCipherSupport {
		code, sev, title := "TLS-050", model.SeverityHigh, "Weak TLS cipher accepted"
		desc := "Server completed TLS 1.2 handshake with only this legacy suite offered—attackers could downgrade clients that support it."
		for _, cs := range tls.InsecureCipherSuites() {
			if cs.Name == name {
				code, sev, title = "TLS-051", model.SeverityCritical, "Insecure TLS cipher accepted"
				desc = "Server accepted a cipher suite classified as insecure (NULL, export, or anon) in Go’s insecure list."
				break
			}
		}
		findings = append(findings, model.Finding{
			Code: code, Severity: sev, Title: title, Description: desc,
			Evidence: fmt.Sprintf("IP %s SNI %q accepted %s (TLS 1.2 only probe)", ip, host, name),
			Remediation: "Remove weak/insecure cipher suites; keep ECDHE+AEAD (GCM/ChaCha).",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
	for _, g := range cap.SupportedGroups {
		findings = append(findings, model.Finding{
			Code: "TLS-070", Severity: model.SeverityInfo, Title: "Key exchange group: " + g,
			Description: "Handshake succeeded when client offered only this named group (ECDHE curve / X25519).",
			Evidence:    fmt.Sprintf("IP %s · group %s", ip, g),
			ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8446#section-7.4.2",
		})
	}
	switch cap.WrongSNIOutcome {
	case "rejected":
		findings = append(findings, model.Finding{
			Code: "TLS-031", Severity: model.SeverityInfo, Title: "Wrong-SNI handshake rejected",
			Description: "Good default: server refuses TLS when SNI does not match a known vhost.",
			Evidence: fmt.Sprintf("IP %s SNI %q rejected", ip, "wrong-sni.invalid"),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
		})
	case "same_cert":
		findings = append(findings, model.Finding{
			Code: "TLS-032", Severity: model.SeverityInfo, Title: "Wrong-SNI but same cert as real host",
			Description: "SNI was garbage yet cert still matches the scan hostname—shared default cert or first-vhost behavior.",
			Evidence: fmt.Sprintf("IP %s SNI %q · served CN %q", ip, "wrong-sni.invalid", cap.WrongSNIFallbackCN),
			Remediation: "Optional hardening: reject unknown SNI instead of serving primary cert.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
		})
	case "fallback_cert":
		findings = append(findings, model.Finding{
			Code: "TLS-033", Severity: model.SeverityInfo, Title: "Wrong-SNI returned fallback cert",
			Description: "Different cert when SNI is wrong—typical multi-tenant or catch-all vhost.",
			Evidence: fmt.Sprintf("IP %s SNI %q · fallback CN %q", ip, "wrong-sni.invalid", cap.WrongSNIFallbackCN),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
		})
	}
	if cap.FallbackSCSVAccepted {
		findings = append(findings, model.Finding{
			Code: "TLS-091", Severity: model.SeverityLow, Title: "TLS fallback SCSV not enforced",
			Description: "Server offers TLS 1.3 but accepted TLS 1.2 ClientHello with FALLBACK_SCSV—RFC 7507 says it should abort with inappropriate_fallback.",
			Evidence:    fmt.Sprintf("IP %s · probe: MaxVersion TLS1.2 + FALLBACK_SCSV, handshake succeeded", ip),
			Remediation: "Upgrade OpenSSL/nginx/etc.; enable strict version handling so fallback probes fail closed.",
			ReferenceURL: "https://www.rfc-editor.org/rfc/rfc7507",
		})
	}
	if cap.NoSNIHandshakeOK {
		findings = append(findings, noSNIFinding(ip, cap.NoSNICertCN, cap.NoSNICertSANs))
	}
	return findings
}

func noSNIFinding(ip, cn string, sans []string) model.Finding {
	return model.Finding{
		Code: "TLS-030", Severity: model.SeverityInfo, Title: "Handshake without SNI succeeded",
		Description: "ClientHello had no ServerName; server still answered—default vhost/cert behavior, not necessarily wrong.",
		Evidence: fmt.Sprintf("IP %s — default cert CN=%q SANs=%v", ip, cn, sans),
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
	}
}
