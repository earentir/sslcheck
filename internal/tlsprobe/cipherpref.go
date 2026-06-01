package tlsprobe

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"sslcheck/internal/model"
)

func probeCipherPreference(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) *model.CipherPreferenceResult {
	_ = parent
	a, okA := tryCipherOrder(parent, host, port, ip, network, timeout, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}, dialer)
	b, okB := tryCipherOrder(parent, host, port, ip, network, timeout, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}, dialer)
	if !okA || !okB {
		return &model.CipherPreferenceResult{Attempted: true}
	}
	return &model.CipherPreferenceResult{
		Attempted:     true,
		ServerPrefers: a == b,
		Observed:      tls.CipherSuiteName(a),
	}
}

func tryCipherOrder(parent context.Context, host, port, ip, network string, timeout time.Duration, suites []uint16, dialer ContextDialer) (uint16, bool) {
	_ = parent
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil { return 0, false }
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, CipherSuites: suites,
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil { return 0, false }
	return conn.ConnectionState().CipherSuite, true
}
