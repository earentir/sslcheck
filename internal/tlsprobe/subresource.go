package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/netx"
)

// ProbeSubresourceHost dials host:port over TLS. resolver and ipVersion ("", "4", "6") match main scan DNS behavior.
func ProbeSubresourceHost(ctx context.Context, host, port string, timeout time.Duration, resolver *net.Resolver, ipVersion string) model.SubresourceHostResult {
	out := model.SubresourceHostResult{Host: host}
	logx.Debug("ProbeSubresourceHost", "host", host)
	r := resolver
	if r == nil {
		r = net.DefaultResolver
	}
	var ips []string
	switch ipVersion {
	case "4":
		list, err := r.LookupIP(ctx, "ip4", host)
		if err == nil {
			for _, ip := range list {
				ips = append(ips, ip.String())
			}
		}
	case "6":
		list, err := r.LookupIP(ctx, "ip6", host)
		if err == nil {
			for _, ip := range list {
				ips = append(ips, ip.String())
			}
		}
	default:
		ips, _ = r.LookupHost(ctx, host)
	}
	out.IPs = ips

	dialCtx := netx.HTTPDialContext(resolver, ipVersion, timeout)
	rawConn, err := dialCtx(ctx, "tcp", net.JoinHostPort(host, port))
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
