package netx

import (
	"context"
	"fmt"
	"net"
	"time"
)

// HTTPDialContext returns a DialContext suitable for http.Transport.DialContext.
// resolver is used for hostname lookups (nil means net.DefaultResolver).
// ipVersion is "", "4", or "6" to restrict connections to one address family.
func HTTPDialContext(resolver *net.Resolver, ipVersion string, dialTimeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	r := resolver
	if r == nil {
		r = net.DefaultResolver
	}
	d := &net.Dialer{Timeout: TCPDialTimeout(dialTimeout), Resolver: r}
	fam := ipVersion
	if fam == "4" {
		fam = "ip4"
	}
	if fam == "6" {
		fam = "ip6"
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			return d.DialContext(ctx, network, addr)
		}
		if fam != "ip4" && fam != "ip6" {
			return d.DialContext(ctx, network, addr)
		}
		ips, err := r.LookupIP(ctx, fam, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no %s addresses for %q", fam, host)
		}
		var firstErr error
		for _, ip := range ips {
			tcpNet := "tcp4"
			if ip.To4() == nil {
				tcpNet = "tcp6"
			}
			target := net.JoinHostPort(ip.String(), port)
			c, err := d.DialContext(ctx, tcpNet, target)
			if err == nil {
				return c, nil
			}
			firstErr = err
		}
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no route to %s", host)
	}
}
