package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"sslcheck/internal/model"
)

var weakCipherTests = []struct {
	Name string
	ID   uint16
	Version uint16
}{
	{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS12},
	{"TLS_RSA_WITH_AES_128_CBC_SHA", tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS12},
	{"TLS_RSA_WITH_AES_256_CBC_SHA", tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS12},
}

func probeWeakCiphers(parent context.Context, host, port, ip, network string, timeout time.Duration, result *model.EndpointResult, dialer ContextDialer) {
	_ = parent
	for _, tc := range weakCipherTests {
		ok := trySpecificCipher(parent, host, port, ip, network, timeout, tc.ID, tc.Version, dialer)
		if !ok { continue }
		result.WeakCipherSupport = append(result.WeakCipherSupport, tc.Name)
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-050", Severity: model.SeverityHigh, Title: "Weak TLS cipher accepted",
			Description: "Server completed TLS 1.2 handshake with only this legacy suite offered—attackers could downgrade clients that support it.",
			Evidence: fmt.Sprintf("IP %s SNI %q accepted %s (TLS 1.2 only probe)", ip, host, tc.Name),
			Remediation: "Remove 3DES, RSA key exchange, and CBC ciphers; keep ECDHE+AEAD (GCM/ChaCha).",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
}

func probeInsecureCiphers(parent context.Context, host, port, ip, network string, timeout time.Duration, result *model.EndpointResult, dialer ContextDialer) {
	_ = parent
	for _, cs := range tls.InsecureCipherSuites() {
		ok := trySpecificCipher(parent, host, port, ip, network, timeout, cs.ID, tls.VersionTLS12, dialer)
		if !ok {
			continue
		}
		name := cs.Name
		result.WeakCipherSupport = append(result.WeakCipherSupport, name)
		result.Findings = append(result.Findings, model.Finding{
			Code: "TLS-051", Severity: model.SeverityCritical, Title: "Insecure TLS cipher accepted",
			Description: "Server accepted a cipher suite classified as insecure (NULL, export, or anon) in Go’s insecure list.",
			Evidence: fmt.Sprintf("IP %s accepted %s", ip, name),
			Remediation: "Disable all NULL, export, and anonymous cipher suites.",
			ReferenceURL: "https://ssl-config.mozilla.org/",
		})
	}
}

func trySpecificCipher(parent context.Context, host, port, ip, network string, timeout time.Duration, cipher uint16, version uint16, dialer ContextDialer) bool {
	_ = parent
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil { return false }
	defer rawConn.Close()
	cfg := &tls.Config{
		ServerName: host, MinVersion: version, MaxVersion: version,
		InsecureSkipVerify: true, CipherSuites: []uint16{cipher},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn.Handshake() == nil
}
