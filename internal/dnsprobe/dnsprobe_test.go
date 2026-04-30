package dnsprobe

import "testing"

func TestNormalizeDNSServerAddr(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"  ", ""},
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		{"dns.google", "dns.google:53"},
	}
	for _, tc := range tests {
		got := normalizeDNSServerAddr(tc.in)
		if got != tc.want {
			t.Errorf("normalizeDNSServerAddr(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
