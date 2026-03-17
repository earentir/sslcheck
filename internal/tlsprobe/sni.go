package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"sslcheck/internal/model"
)

func probeWrongSNI(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) []model.Finding {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	badName := "wrong-sni.invalid"
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil { return nil }
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName: badName, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return []model.Finding{{
			Code: "TLS-031", Severity: model.SeverityInfo, Title: "Wrong-SNI handshake rejected",
			Description: "Good default: server refuses TLS when SNI does not match a known vhost.",
			Evidence: fmt.Sprintf("IP %s SNI %q → %v", ip, badName, err),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
		}}
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 { return nil }
	leaf := state.PeerCertificates[0]
	if err := leaf.VerifyHostname(host); err == nil {
		return []model.Finding{{
			Code: "TLS-032", Severity: model.SeverityInfo, Title: "Wrong-SNI but same cert as real host",
			Description: "SNI was garbage yet cert still matches the scan hostname—shared default cert or first-vhost behavior.",
			Evidence: fmt.Sprintf("IP %s SNI %q · served CN %q", ip, badName, leaf.Subject.CommonName),
			Remediation: "Optional hardening: reject unknown SNI instead of serving primary cert.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
		}}
	}
	return []model.Finding{{
		Code: "TLS-033", Severity: model.SeverityInfo, Title: "Wrong-SNI returned fallback cert",
		Description: "Different cert when SNI is wrong—typical multi-tenant or catch-all vhost.",
		Evidence: fmt.Sprintf("IP %s SNI %q · fallback CN %q", ip, badName, leaf.Subject.CommonName),
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6066#section-3",
	}}
}
