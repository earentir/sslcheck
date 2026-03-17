package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"sslcheck/internal/model"
)

// probeTLSFallbackSCSV checks whether the server rejects a TLS fallback client hello
// (RFC 7507). Only runs when the server supports TLS 1.3. If a client connects
// with MaxVersion TLS 1.2 and sends FALLBACK_SCSV, a compliant server that supports
// TLS 1.3 should reject with inappropriate_fallback. If the handshake succeeds, we
// report that fallback SCSV is not enforced.
func probeTLSFallbackSCSV(parent context.Context, host, port, ip, network string, timeout time.Duration, result *model.EndpointResult, dialer ContextDialer) {
	if !result.ProtocolSupport["TLS1.3"] {
		return
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil {
		return
	}
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		CipherSuites:        []uint16{tls.TLS_FALLBACK_SCSV, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		NextProtos:          []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	err = conn.Handshake()
	if err != nil {
		return
	}
	_ = conn.Close()
	result.Findings = append(result.Findings, model.Finding{
		Code: "TLS-091", Severity: model.SeverityLow, Title: "TLS fallback SCSV not enforced",
		Description: "Server offers TLS 1.3 but accepted TLS 1.2 ClientHello with FALLBACK_SCSV—RFC 7507 says it should abort with inappropriate_fallback.",
		Evidence:    fmt.Sprintf("IP %s · probe: MaxVersion TLS1.2 + FALLBACK_SCSV, handshake succeeded", ip),
		Remediation: "Upgrade OpenSSL/nginx/etc.; enable strict version handling so fallback probes fail closed.",
		ReferenceURL: "https://www.rfc-editor.org/rfc/rfc7507",
	})
}
