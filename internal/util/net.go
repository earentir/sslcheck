package util

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// NormalizeURL parses a scan target. If there is no scheme (e.g. "example.com"),
// "https://" is prepended. "http://" is normalized to "https://" for TLS checks.
func NormalizeURL(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("empty URL")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if strings.EqualFold(u.Scheme, "http") {
		u.Scheme = "https"
		host := u.Hostname()
		port := u.Port()
		if port == "80" || port == "" {
			u.Host = host
		} else {
			u.Host = net.JoinHostPort(host, port)
		}
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("only http(s) URLs or bare hostnames are supported")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing hostname")
	}
	return u, nil
}

func NetworkForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		return "tcp6"
	}
	return "tcp4"
}

func UniqueSortedStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
