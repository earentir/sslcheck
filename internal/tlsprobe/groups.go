package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"sslcheck/internal/model"
)

func probeSupportedGroups(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) []model.Finding {
	_ = parent
	tests := []struct {
		Name string
		Group tls.CurveID
	}{
		{"X25519", tls.X25519},
		{"P-256", tls.CurveP256},
		{"P-384", tls.CurveP384},
	}
	var findings []model.Finding
	for _, tc := range tests {
		ok, err := tryCurve(parent, host, port, ip, network, timeout, tc.Group, dialer)
		if err != nil || !ok { continue }
		findings = append(findings, model.Finding{
			Code: "TLS-070", Severity: model.SeverityInfo, Title: "Key exchange group: " + tc.Name,
			Description: "Handshake succeeded when client offered only this named group (ECDHE curve / X25519).",
			Evidence: fmt.Sprintf("IP %s · group %s", ip, tc.Name),
			ReferenceURL: "https://www.rfc-editor.org/rfc/rfc8446#section-7.4.2",
		})
	}
	return findings
}

func tryCurve(parent context.Context, host, port, ip, network string, timeout time.Duration, group tls.CurveID, dialer ContextDialer) (bool, error) {
	_ = parent
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil { return false, err }
	defer rawConn.Close()
	cfg := &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{group},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil { return false, err }
	return true, nil
}
