package tlsprobe

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"sslcheck/internal/model"
)

func probeALPN(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) *model.ALPNResult {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	h2OK, h2Err := tryALPN(parent, host, port, ip, network, timeout, []string{"h2"}, dialer)
	h11OK, h11Err := tryALPN(parent, host, port, ip, network, timeout, []string{"http/1.1"}, dialer)
	return &model.ALPNResult{
		H2WhenOnly: h2OK, HTTP11WhenOnly: h11OK,
		H2OnlyError: h2Err, HTTP11OnlyError: h11Err,
	}
}

func tryALPN(parent context.Context, host, port, ip, network string, timeout time.Duration, protos []string, dialer ContextDialer) (bool, string) {
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil { return false, err.Error() }
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: protos,
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil { return false, err.Error() }
	state := conn.ConnectionState()
	return state.NegotiatedProtocol == protos[0], ""
}
