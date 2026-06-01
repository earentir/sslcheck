package dnsprobe

import "testing"

func TestSplitIPFamilies(t *testing.T) {
	fam := SplitIPFamilies([]string{"192.0.2.1", "2001:db8::1", "10.0.0.1"})
	if len(fam.IPv4) != 2 || len(fam.IPv6) != 1 {
		t.Fatalf("IPv4=%v IPv6=%v", fam.IPv4, fam.IPv6)
	}
}

func TestFamilyFindings(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want string
	}{
		{"dual stack", []string{"192.0.2.1", "2001:db8::1"}, "DNS-020"},
		{"ipv6 only", []string{"2001:db8::1"}, "DNS-021"},
		{"ipv4 only", []string{"192.0.2.1"}, "DNS-022"},
		{"empty", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FamilyFindings(tt.ips)
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected no findings, got %#v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Code != tt.want {
				t.Fatalf("got %#v want code %s", got, tt.want)
			}
		})
	}
}
