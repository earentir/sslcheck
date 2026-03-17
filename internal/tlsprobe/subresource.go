package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
)

func ProbeSubresourceHost(ctx context.Context, host, port string, timeout time.Duration) model.SubresourceHostResult {
	out := model.SubresourceHostResult{Host: host}
	logx.Debug("ProbeSubresourceHost", "host", host)
	ips, _ := net.DefaultResolver.LookupHost(ctx, host)
	out.IPs = ips
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		out.Error = err.Error()
		logx.Debug("subresource TCP fail", "host", host, "err", err.Error())
		return out
	}
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		out.Error = err.Error()
		logx.Debug("subresource TLS handshake fail", "host", host, "err", err.Error())
		return out
	}

	out.TLSOK = true
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		out.HostnameMatchOK = leaf.VerifyHostname(host) == nil
		roots, err := x509.SystemCertPool()
		if err == nil && roots != nil {
			intermediates := x509.NewCertPool()
			for i := 1; i < len(state.PeerCertificates); i++ {
				intermediates.AddCert(state.PeerCertificates[i])
			}
			_, err = leaf.Verify(x509.VerifyOptions{
				DNSName: host, Roots: roots, Intermediates: intermediates,
				CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			out.TrustOK = err == nil
			if err != nil && out.Error == "" {
				out.Error = err.Error()
			}
		}
	}
	logx.Debug("subresource TLS OK", "host", host, "trust", out.TrustOK, "hostname_match", out.HostnameMatchOK)
	return out
}
