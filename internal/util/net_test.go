package util

import (
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantHost string
		wantErr  bool
	}{
		{"valid https", "https://example.com", "example.com", false},
		{"valid https with path", "https://example.com/path", "example.com", false},
		{"valid https with port", "https://example.com:443/", "example.com", false},
		{"bare hostname", "example.com", "example.com", false},
		{"bare host with subdomain", "earentir.dev", "earentir.dev", false},
		{"bare host trim", "  example.com  ", "example.com", false},
		{"bare host port", "example.com:8443", "example.com", false},
		{"http to https", "http://example.com", "example.com", false},
		{"http port 8080", "http://example.com:8080", "example.com", false},
		{"ftp unsupported", "ftp://example.com", "", true},
		{"missing hostname", "https://", "", true},
		{"invalid URL", "://bad", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := NormalizeURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if u.Hostname() != tt.wantHost {
				t.Errorf("NormalizeURL() host = %q, want %q", u.Hostname(), tt.wantHost)
			}
		})
	}
}

func TestNormalizeURL_HTTPBecomesHTTPS(t *testing.T) {
	u, err := NormalizeURL("http://example.com/path")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" {
		t.Errorf("scheme = %q", u.Scheme)
	}
	if u.Hostname() != "example.com" {
		t.Errorf("host = %q", u.Hostname())
	}
}

func TestNetworkForIP(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"127.0.0.1", "tcp4"},
		{"192.168.1.1", "tcp4"},
		{"::1", "tcp6"},
		{"2001:db8::1", "tcp6"},
		{"invalid", "tcp4"}, // ParseIP returns nil, To4() is nil on invalid so we get tcp6? No - parsed is nil, so To4() is not called. Check code: if parsed != nil && parsed.To4() == nil -> tcp6. So for "invalid", parsed is nil, we fall through to return "tcp4". So invalid IP returns tcp4.
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := NetworkForIP(tt.ip)
			if got != tt.want {
				t.Errorf("NetworkForIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestUniqueSortedStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{}},
		{"single", []string{"a"}, []string{"a"}},
		{"dedup", []string{"b", "a", "b", "a"}, []string{"a", "b"}},
		{"already sorted", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"reverse", []string{"c", "b", "a"}, []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UniqueSortedStrings(tt.in)
			if len(got) != len(tt.want) {
				t.Errorf("UniqueSortedStrings() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("UniqueSortedStrings()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
