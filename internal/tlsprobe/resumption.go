package tlsprobe

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"sslcheck/internal/model"
)

func probeResumption(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) *model.ResumptionResult {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	return &model.ResumptionResult{
		TLS12Attempted: true,
		TLS12Resumed:   tryResumption(parent, host, port, ip, network, timeout, tls.VersionTLS12, dialer),
		TLS13Attempted: true,
		TLS13Resumed:   tryResumption(parent, host, port, ip, network, timeout, tls.VersionTLS13, dialer),
	}
}

func tryResumption(parent context.Context, host, port, ip, network string, timeout time.Duration, version uint16, dialer ContextDialer) bool {
	cache := tls.NewLRUClientSessionCache(8)
	if _, err := resumedHandshake(parent, host, port, ip, network, timeout, version, cache, dialer); err != nil {
		return false
	}
	resumed, err := resumedHandshake(parent, host, port, ip, network, timeout, version, cache, dialer)
	return err == nil && resumed
}

func resumedHandshake(parent context.Context, host, port, ip, network string, timeout time.Duration, version uint16, cache tls.ClientSessionCache, dialer ContextDialer) (bool, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialer.DialContext(parent, network, addr)
	if err != nil { return false, err }
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName: host, MinVersion: version, MaxVersion: version,
		InsecureSkipVerify: true, ClientSessionCache: cache,
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil { return false, err }
	return conn.ConnectionState().DidResume, nil
}
