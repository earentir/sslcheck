package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/util"
)

// ContextDialer dials with context support. When nil, default net.Dialer is used.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Options struct {
	SkipActiveOCSP bool
	DialContext    ContextDialer // optional; when set, used for all TCP dials (e.g. via proxy)
	// FetchHTTP is used for AIA and active OCSP HTTP requests; should use the same DNS policy as the scan.
	FetchHTTP *http.Client
}

func ProbeEndpoint(parent context.Context, host, port, ip string, timeout time.Duration, opts Options) model.EndpointResult {
	network := util.NetworkForIP(ip)
	result := model.EndpointResult{
		IP: ip, Network: network, ProtocolSupport: make(map[string]bool),
	}

	addr := net.JoinHostPort(ip, port)
	dialer := opts.DialContext
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	logx.Debug("TLS TCP dial", "host", host, "ip", ip, "addr", addr, "network", network)
	start := time.Now()
	tcpConn, err := dialer.DialContext(parent, network, addr)
	if err != nil {
		logx.Warn("TLS TCP failed", "host", host, "ip", ip, "err", err.Error())
		result.Errors = append(result.Errors, "tcp connect failed: "+err.Error())
		result.Findings = append(result.Findings, tcpDialFinding(network, ip, err))
		return result
	}
	result.TCPReachable = true
	result.TCPConnectLatency = time.Since(start).String()
	logx.Debug("TLS TCP OK", "ip", ip, "latency", result.TCPConnectLatency)
	_ = tcpConn.Close()

	logx.Debug("probe protocol versions", "ip", ip)
	probeProtocolVersions(parent, host, port, ip, network, timeout, &result, dialer)
	logx.Debug("probe weak ciphers", "ip", ip)
	probeWeakCiphers(parent, host, port, ip, network, timeout, &result, dialer)

	logx.Debug("TLS best handshake", "ip", ip, "sni", host)
	bestState, rawChain, err := probeBestHandshake(parent, host, port, ip, network, timeout, dialer)
	if err != nil {
		logx.Warn("TLS handshake failed", "ip", ip, "err", err.Error())
		result.Errors = append(result.Errors, "tls handshake failed: "+err.Error())
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-001", Severity: model.SeverityCritical, Title: "TLS handshake failed",
			Description: "Could not complete TLS with this IP after TCP connected—often wrong cert/SNI, TLS disabled on this vhost, or cipher/protocol mismatch.",
			Evidence: fmt.Sprintf("IP %s, SNI %q, error: %v", ip, host, err),
			Remediation: "On the server: enable TLS on 443, set correct ServerName/SNI vhost, allow TLS 1.2+, and present a valid chain for this hostname.",
			ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
		})
		probeNoSNI(parent, host, port, ip, network, timeout, &result, dialer)
		return result
	}

	result.TLSHandshakeOK = true
	logx.Info("TLS handshake OK", "ip", ip, "version", util.TLSVersionString(bestState.Version), "cipher", tls.CipherSuiteName(bestState.CipherSuite), "alpn", bestState.NegotiatedProtocol, "peer_certs", len(bestState.PeerCertificates))
	result.TLSVersion = util.TLSVersionString(bestState.Version)
	result.CipherSuite = tls.CipherSuiteName(bestState.CipherSuite)
	result.ServerName = bestState.ServerName
	result.ALPN = bestState.NegotiatedProtocol
	result.ALPNProbe = probeALPN(parent, host, port, ip, network, timeout, dialer)
	result.Resumption = probeResumption(parent, host, port, ip, network, timeout, dialer)
	result.CipherPreference = probeCipherPreference(parent, host, port, ip, network, timeout, dialer)
	result.PeerCertCount = len(bestState.PeerCertificates)
	result.OCSPStapled = len(bestState.OCSPResponse) > 0
	result.SCTCount = len(bestState.SignedCertificateTimestamps)

	if result.OCSPStapled {
		if status, err := parseOCSPStatus(bestState.OCSPResponse, rawChain); err == nil {
			result.OCSPStatus = status
		} else {
			result.Warnings = append(result.Warnings, "ocsp stapling present but parse failed: "+err.Error())
		}
	} else if summaryChainHasOCSP(rawChain) {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-021", Severity: model.SeverityInfo, Title: "OCSP stapling not offered",
			Description: "The leaf cert lists an OCSP URL, but the TLS handshake had no stapled OCSP response—clients must query the CA instead.",
			Evidence: fmt.Sprintf("IP %s · OCSP URLs on cert: %s", ip, strings.Join(bestState.PeerCertificates[0].OCSPServer, ", ")),
			Remediation: "Enable OCSP stapling in your web server (e.g. nginx ssl_stapling, Apache SSLUseStapling).",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#ocsp_stapling",
		})
	}

	logx.Debug("chain build AIA extend", "ip", ip, "raw_certs", len(rawChain))
	chainBuild := ExtendChainWithAIA(parent, host, rawChain, timeout, opts.FetchHTTP)
	logx.Debug("chain build result", "ip", ip, "full_len", len(chainBuild.Chain), "verified", chainBuild.VerifiedOK, "notes", len(chainBuild.Notes))
	fullChain := chainBuild.Chain
	summary, certFindings := analyzeCertificates(host, fullChain)
	result.CertSummary = summary
	result.Findings = append(result.Findings, certFindings...)
	result.Findings = append(result.Findings, lintChain(fullChain, len(rawChain))...)
	result.CertificateChainDetails = buildChainCertificateDetails(fullChain, rawChain, chainBuild.FetchedFP)
	result.ChainBuildNotes = append([]string(nil), chainBuild.Notes...)
	if !chainBuild.VerifiedOK && len(fullChain) > 0 {
		result.ChainBuildNotes = append(result.ChainBuildNotes,
			"Chain not fully verified to a system trust anchor with the built path (see certificate findings).")
	}
	if !opts.SkipActiveOCSP {
		result.Findings = append(result.Findings, checkOCSPURLs(parent, rawChain, opts.FetchHTTP)...)
	}

	if bestState.Version <= tls.VersionTLS11 {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-010", Severity: model.SeverityCritical, Title: "Legacy TLS negotiated",
			Description: "The best handshake used TLS 1.0 or 1.1, which are deprecated and unsafe for HTTPS.",
			Evidence: fmt.Sprintf("IP %s negotiated %s (cipher %s)", ip, result.TLSVersion, result.CipherSuite),
			Remediation: "Set minimum TLS to 1.2 (prefer 1.3). Remove TLS 1.0/1.1 from all listeners and load balancers.",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
	if result.ALPN == "" {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-020", Severity: model.SeverityInfo, Title: "No ALPN negotiated",
			Description: "ALPN was empty after handshake—common for non-HTTP TLS or very old stacks; HTTP/2 over TLS usually needs h2 in ALPN.",
			Evidence: fmt.Sprintf("IP %s, SNI %q — negotiated ALPN: (empty)", ip, host),
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/ALPN",
		})
	}
	if result.ALPNProbe != nil && !result.ALPNProbe.H2WhenOnly {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-022", Severity: model.SeverityInfo, Title: "HTTP/2 ALPN not negotiated",
			Description: "We offered only h2; server did not select it—this IP may be serving HTTP/1.1-only over TLS or rejecting the probe.",
			Evidence: fmt.Sprintf("IP %s", ip),
			Remediation: "Enable HTTP/2 (and ALPN h2) if you want H2 on this endpoint.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/HTTP_2",
		})
	}
	if result.Resumption != nil {
		if !result.Resumption.TLS12Resumed && result.ProtocolSupport["TLS1.2"] {
			result.Findings = append(result.Findings, model.Finding{
				Code: "TLS-060", Severity: model.SeverityInfo, Title: "TLS 1.2 session resumption not observed",
				Description: "Second handshake did not show TLS 1.2 resumption (tickets/IDs)—may still work with different timing or server policy.",
				Evidence: fmt.Sprintf("IP %s", ip),
				ReferenceURL: "https://wiki.openssl.org/index.php/TLS1.3#Session_Resumption",
			})
		}
		if !result.Resumption.TLS13Resumed && result.ProtocolSupport["TLS1.3"] {
			result.Findings = append(result.Findings, model.Finding{
				Code: "TLS-061", Severity: model.SeverityInfo, Title: "TLS 1.3 session resumption not observed",
				Description: "TLS 1.3 PSK/ticket resumption was not observed on retry—not always a misconfiguration.",
				Evidence: fmt.Sprintf("IP %s", ip),
				ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8446#section-2.2",
			})
		}
	}
	if result.CipherPreference != nil && result.CipherPreference.Attempted && result.CipherPreference.ServerPrefers {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-090", Severity: model.SeverityInfo, Title: "Server cipher preference observed",
			Description: "Server picks cipher order (not client)—normal; ensure server list prioritizes AEAD (GCM/ChaCha) over CBC.",
			Evidence: fmt.Sprintf("IP %s negotiated %s with reordered client suites", ip, result.CipherPreference.Observed),
			ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
		})
	}
	if result.SCTCount == 0 {
		result.Findings = append(result.Findings, model.Finding{
			Code: "CERT-040", Severity: model.SeverityInfo, Title: "No SCTs in handshake",
			Description: "No embedded SCTs in the cert/handshake—CT may still be satisfied via embedded certs or logs.",
			Evidence: fmt.Sprintf("IP %s, leaf serial %s", ip, bestState.PeerCertificates[0].SerialNumber.Text(16)),
			ReferenceURL: "https://certificate.transparency.dev/",
		})
	}

	probeNoSNI(parent, host, port, ip, network, timeout, &result, dialer)
	result.Findings = append(result.Findings, probeWrongSNI(parent, host, port, ip, network, timeout, dialer)...)
	result.Findings = append(result.Findings, probeSupportedGroups(parent, host, port, ip, network, timeout, dialer)...)
	probeTLSFallbackSCSV(parent, host, port, ip, network, timeout, &result, dialer)
	model.SortFindings(result.Findings)
	return result
}

func probeProtocolVersions(parent context.Context, host, port, ip, network string, timeout time.Duration, result *model.EndpointResult, dialer ContextDialer) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	versions := []struct{ Name string; ID uint16 }{
		{"TLS1.0", tls.VersionTLS10}, {"TLS1.1", tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12}, {"TLS1.3", tls.VersionTLS13},
	}
	for _, v := range versions {
		supported := tryTLSVersion(parent, host, port, ip, network, timeout, v.ID, dialer)
		result.ProtocolSupport[v.Name] = supported
		if v.ID <= tls.VersionTLS11 && supported {
			result.Findings = append(result.Findings, model.Finding{
				Code: "TLS-011", Severity: model.SeverityCritical, Title: "Legacy TLS version supported",
				Description: "A separate probe confirmed this IP still completes handshakes on TLS 1.0/1.1—downgrade attacks become possible.",
				Evidence: fmt.Sprintf("IP %s accepts %s (dedicated version probe)", ip, v.Name),
				Remediation: "Disable TLS 1.0 and 1.1 everywhere (LB + origin).",
				ReferenceURL: "https://ssl-config.mozilla.org/",
			})
		}
	}
	if !result.ProtocolSupport["TLS1.2"] && !result.ProtocolSupport["TLS1.3"] {
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-012", Severity: model.SeverityCritical, Title: "No modern TLS support",
			Description: "Neither TLS 1.2 nor 1.3 completed in our version probes—browsers will fail or use only legacy TLS.",
			Evidence: fmt.Sprintf("IP %s protocol map: %+v", ip, result.ProtocolSupport),
			Remediation: "Enable TLS 1.2 minimum; add TLS 1.3 where possible.",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
}

func tryTLSVersion(parent context.Context, host, port, ip, network string, timeout time.Duration, version uint16, dialer ContextDialer) bool {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil { return false }
	defer rawConn.Close()
	cfg := &tls.Config{
		ServerName: host, MinVersion: version, MaxVersion: version,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn.Handshake() == nil
}

func probeBestHandshake(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) (tls.ConnectionState, []*x509.Certificate, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil { return tls.ConnectionState{}, nil, err }
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil { return tls.ConnectionState{}, nil, err }
	state := conn.ConnectionState()
	return state, state.PeerCertificates, nil
}

func probeNoSNI(parent context.Context, host, port, ip, network string, timeout time.Duration, result *model.EndpointResult, dialer ContextDialer) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil { result.TLSErrorNoSNI = err.Error(); return }
	defer rawConn.Close()

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil { result.TLSErrorNoSNI = err.Error(); return }

	result.NoSNIHandshakeOK = true
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		result.NoSNICertCN = state.PeerCertificates[0].Subject.CommonName
		result.NoSNICertSANs = append([]string(nil), state.PeerCertificates[0].DNSNames...)
	}
	result.Findings = append(result.Findings, model.Finding{
		Code: "TLS-030", Severity: model.SeverityInfo, Title: "Handshake without SNI succeeded",
		Description: "ClientHello had no ServerName; server still answered—default vhost/cert behavior, not necessarily wrong.",
		Evidence: fmt.Sprintf("IP %s — default cert CN=%q SANs=%v", ip, result.NoSNICertCN, result.NoSNICertSANs),
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
	})
}

func analyzeCertificates(host string, chain []*x509.Certificate) (*model.CertificateSummary, []model.Finding) {
	if len(chain) == 0 {
		return nil, []model.Finding{{
			Code: "CERT-001", Severity: model.SeverityCritical, Title: "No certificate presented",
			Description: "Handshake succeeded but no peer certificate chain was returned—invalid for HTTPS.",
			Evidence: "PeerCertificates length 0 after successful handshake",
			Remediation: "Configure the TLS listener to send the server certificate chain.",
			ReferenceURL: "https://wiki.mozilla.org/Security/Server_Side_TLS",
		}}
	}
	leaf := chain[0]
	summary := &model.CertificateSummary{
		SubjectCommonName: leaf.Subject.CommonName,
		DNSNames: append([]string(nil), leaf.DNSNames...),
		IssuerCommonName: leaf.Issuer.CommonName,
		SerialNumber: leaf.SerialNumber.Text(16),
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry: int(time.Until(leaf.NotAfter).Hours()/24),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
		PublicKeyStrength: util.PublicKeyStrength(leaf),
		KeyUsage: util.KeyUsageStrings(leaf.KeyUsage),
		ExtKeyUsage: util.ExtKeyUsageStrings(leaf.ExtKeyUsage),
		IsCA: leaf.IsCA,
		OCSPServers: append([]string(nil), leaf.OCSPServer...),
		CRLDistribution: append([]string(nil), leaf.CRLDistributionPoints...),
	}
	for _, c := range chain {
		summary.ChainSubjects = append(summary.ChainSubjects, util.SubjectLine(c))
	}

	var findings []model.Finding
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		findings = append(findings, model.Finding{
			Code: "CERT-010", Severity: model.SeverityCritical, Title: "Certificate not yet valid",
			Description: "Current time is before NotBefore—clients will reject until that instant.",
			Evidence: fmt.Sprintf("NotBefore %s · NotAfter %s (now UTC)", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339)),
			Remediation: "Deploy a cert already in validity, or fix server clock skew.",
			ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
		})
	}
	if now.After(leaf.NotAfter) {
		findings = append(findings, model.Finding{
			Code: "CERT-011", Severity: model.SeverityCritical, Title: "Certificate expired",
			Description: "NotAfter is in the past—browsers show certificate errors.",
			Evidence: fmt.Sprintf("NotAfter %s · subject %s", leaf.NotAfter.UTC().Format(time.RFC3339), leaf.Subject.CommonName),
			Remediation: "Issue a new cert and reload TLS; automate renewal (ACME etc.).",
			ReferenceURL: "https://letsencrypt.org/getting-started/",
		})
	} else if summary.DaysUntilExpiry <= 7 {
		findings = append(findings, model.Finding{
			Code: "CERT-012", Severity: model.SeverityHigh, Title: "Certificate expires soon",
			Description: "Less than 8 days until NotAfter.",
			Evidence: fmt.Sprintf("%d days until %s", summary.DaysUntilExpiry, leaf.NotAfter.UTC().Format(time.RFC3339)),
			Remediation: "Renew now; shorten renewal automation window if this is recurring.",
			ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
		})
	} else if summary.DaysUntilExpiry <= 30 {
		findings = append(findings, model.Finding{
			Code: "CERT-013", Severity: model.SeverityMedium, Title: "Certificate expiry approaching",
			Description: "30 days or fewer remaining—plan renewal before busy period.",
			Evidence: fmt.Sprintf("%d days until %s", summary.DaysUntilExpiry, leaf.NotAfter.UTC().Format(time.RFC3339)),
			Remediation: "Schedule renewal and test staging deploy.",
			ReferenceURL: "https://letsencrypt.org/docs/integration-guide/",
		})
	}

	if err := leaf.VerifyHostname(host); err != nil {
		summary.HostnameVerifyError = err.Error()
		findings = append(findings, model.Finding{
			Code: "CERT-020", Severity: model.SeverityCritical, Title: "Certificate hostname mismatch",
			Description: "Requested name is not in leaf SAN/CN per Go’s hostname verification.",
			Evidence: fmt.Sprintf("host %q: %v · cert DNSNames: %v", host, err, leaf.DNSNames),
			Remediation: "Reissue with SAN covering this exact hostname (and www if needed).",
			ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
		})
	} else {
		summary.HostnameVerified = true
	}

	roots, err := x509.SystemCertPool()
	if err == nil && roots != nil {
		intermediates := x509.NewCertPool()
		for i := 1; i < len(chain); i++ { intermediates.AddCert(chain[i]) }
		_, verr := leaf.Verify(x509.VerifyOptions{
			DNSName: host, Roots: roots, Intermediates: intermediates,
			CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if verr != nil {
			summary.TrustError = verr.Error()
			findings = append(findings, model.Finding{
				Code: "CERT-021", Severity: model.SeverityCritical, Title: "Certificate chain is not trusted",
				Description: "System roots + presented intermediates could not build a path to a trusted anchor.",
				Evidence: fmt.Sprintf("%v · chain subjects: %v", verr, summary.ChainSubjects),
				Remediation: "Install missing intermediate(s) on the server; avoid self-signed for public sites.",
				ReferenceURL: "https://wiki.mozilla.org/CA/Included_Certificates",
			})
		} else {
			summary.TrustVerified = true
		}
	}

	switch leaf.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		findings = append(findings, model.Finding{
			Code: "CERT-030", Severity: model.SeverityHigh, Title: "Weak certificate signature algorithm",
			Description: "Signature uses MD5/MD2/SHA1-class algorithm—deprecated for TLS server certs.",
			Evidence: leaf.SignatureAlgorithm.String(),
			Remediation: "Reissue with SHA-256+ (e.g. sha256WithRSAEncryption, ecdsa-with-SHA256).",
			ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
		})
	}
	findings = append(findings, publicKeyFindings(leaf)...)

	if len(leaf.OCSPServer) == 0 {
		findings = append(findings, model.Finding{
			Code: "CERT-041", Severity: model.SeverityInfo, Title: "No OCSP responder URI",
			Description: "No OCSPServer extension—some CAs still issue this way; stapling/revocation behavior differs.",
			Evidence: fmt.Sprintf("subject %s", leaf.Subject.CommonName),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6960",
		})
	}
	if len(leaf.CRLDistributionPoints) == 0 {
		findings = append(findings, model.Finding{
			Code: "CERT-042", Severity: model.SeverityInfo, Title: "No CRL distribution points",
			Description: "No CRLDistributionPoints—revocation may rely on OCSP-only or platform behavior.",
			Evidence: fmt.Sprintf("subject %s", leaf.Subject.CommonName),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13",
		})
	}
	return summary, findings
}

func publicKeyFindings(cert *x509.Certificate) []model.Finding {
	var findings []model.Finding
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pk.N.BitLen() < 2048 {
			findings = append(findings, model.Finding{
				Code: "CERT-031", Severity: model.SeverityHigh, Title: "Weak RSA key size",
				Description: "RSA public key under 2048 bits does not meet current baseline requirements.",
				Evidence: fmt.Sprintf("%d bits", pk.N.BitLen()),
				Remediation: "Reissue with ≥2048-bit RSA or EC P-256+.",
				ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
			})
		} else if pk.N.BitLen() < 3072 {
			findings = append(findings, model.Finding{
				Code: "CERT-032", Severity: model.SeverityInfo, Title: "RSA 2048 (acceptable)",
				Description: "2048-bit RSA is still widely accepted; 3072 or EC can be preferred for long-lived certs.",
				Evidence: fmt.Sprintf("%d bits RSA", pk.N.BitLen()),
				ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
			})
		}
	case *ecdsa.PublicKey:
		if pk.Curve.Params().Name == "P-224" {
			findings = append(findings, model.Finding{
				Code: "CERT-033", Severity: model.SeverityHigh, Title: "Weak ECDSA curve",
				Description: "P-224 and weaker curves are not appropriate for TLS server authentication.",
				Evidence: pk.Curve.Params().Name,
				Remediation: "Reissue with P-256, P-384, or P-521.",
				ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8422",
			})
		}
	case ed25519.PublicKey:
	default:
		findings = append(findings, model.Finding{
			Code: "CERT-034", Severity: model.SeverityInfo, Title: "Unexpected public key type",
			Description: "Public key algorithm is not RSA/ECDSA/Ed25519 in our usual paths—investigate client compatibility.",
			Evidence: cert.PublicKeyAlgorithm.String(),
			ReferenceURL: "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
		})
	}
	return findings
}

func summaryChainHasOCSP(chain []*x509.Certificate) bool {
	return len(chain) > 0 && len(chain[0].OCSPServer) > 0
}

func parseOCSPStatus(raw []byte, chain []*x509.Certificate) (string, error) {
	if len(raw) == 0 { return "", fmt.Errorf("no stapled OCSP response") }
	if len(chain) < 2 { return "", fmt.Errorf("cannot parse OCSP without issuer certificate") }
	resp, err := ocsp.ParseResponse(raw, chain[1])
	if err != nil { return "", err }
	switch resp.Status {
	case ocsp.Good:
		return "good", nil
	case ocsp.Revoked:
		return "revoked", nil
	case ocsp.Unknown:
		return "unknown", nil
	default:
		return fmt.Sprintf("status-%d", resp.Status), nil
	}
}

// tcpDialFailureFromScannerRouting matches errors where the scanner OS/network has no path
// (e.g. no IPv6 on the client) rather than the server refusing the connection.
func tcpDialFailureFromScannerRouting(network string, err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route available")
}

func tcpDialFinding(network, ip string, err error) model.Finding {
	ev := fmt.Sprintf("%s (%s): %v", ip, network, err)
	if tcpDialFailureFromScannerRouting(network, err) {
		fam := "IPv6"
		if network == "tcp4" {
			fam = "IPv4"
		}
		return model.Finding{
			Code: "NET-002", Severity: model.SeverityInfo,
			Title: fam + " unreachable from scanner (routing)",
			Description: "TCP dial failed with a routing error on this machine (e.g. no route to host). " +
				"Usually the scanner cannot use " + fam + " to reach the target—not proof the server is down.",
			Evidence:    ev,
			Remediation: "Compare the other address family if listed. Scan from a network with " + fam + " or rely on the stack that works.",
			ReferenceURL: "https://en.wikipedia.org/wiki/IPv6#Deployment",
		}
	}
	return model.Finding{
		Code: "NET-001", Severity: model.SeverityHigh, Title: "TCP connection failed",
		Description: "Could not open a TCP connection to this IP:port (refused, timeout, or reset).",
		Evidence:    ev,
		Remediation: "From the server side: listen on 443, security group/firewall allows INBOUND TCP to this IP, correct backend pool.",
		ReferenceURL: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
	}
}
