package dnsprobe

import "testing"

func TestResolverForDNSServer_Default(t *testing.T) {
	r := ResolverForDNSServer("")
	if r == nil {
		t.Fatal("nil resolver")
	}
}

func TestResolverForDNSServer_CustomPreferGo(t *testing.T) {
	r := ResolverForDNSServer("1.1.1.1")
	if r == nil || !r.PreferGo {
		t.Fatalf("expected PreferGo custom resolver, got %+v", r)
	}
}
