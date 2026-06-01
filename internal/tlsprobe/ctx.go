package tlsprobe

import (
	"context"
	"net"
	"time"

	"sslcheck/internal/netx"
)

func probeContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

func tcpDialTimeout(op time.Duration) time.Duration {
	return netx.TCPDialTimeout(op)
}

func defaultDialer(timeout time.Duration) ContextDialer {
	return &net.Dialer{Timeout: tcpDialTimeout(timeout)}
}

// dialTCP opens a TCP connection with an isolated deadline (not shared across probe steps).
func dialTCP(dialer ContextDialer, timeout time.Duration, network, addr string) (net.Conn, error) {
	if dialer == nil {
		dialer = defaultDialer(timeout)
	}
	ctx, cancel := probeContext(timeout)
	defer cancel()
	return dialer.DialContext(ctx, network, addr)
}
