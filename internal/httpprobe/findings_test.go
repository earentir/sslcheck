package httpprobe

import (
	"net/url"
	"testing"

	"sslcheck/internal/model"
)

func TestRedirectFindings(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		fs := RedirectFindings(model.HTTPRedirectResult{Error: "timeout"})
		if len(fs) != 1 || fs[0].Code != "HTTP-001" {
			t.Fatalf("got %#v", fs)
		}
	})
	t.Run("no https redirect", func(t *testing.T) {
		fs := RedirectFindings(model.HTTPRedirectResult{
			HTTPURL: "http://example.com", StatusCode: 200, Location: "http://example.com/",
		})
		if len(fs) != 1 || fs[0].Code != "HTTP-002" {
			t.Fatalf("got %#v", fs)
		}
	})
	t.Run("redirects to https", func(t *testing.T) {
		fs := RedirectFindings(model.HTTPRedirectResult{
			RedirectsToHTTPS: true, Location: "https://example.com/",
		})
		if len(fs) != 1 || fs[0].Code != "HTTP-003" {
			t.Fatalf("got %#v", fs)
		}
	})
}

func TestParseHSTS(t *testing.T) {
	var r model.HTTPResult
	parseHSTS("max-age=31536000; includeSubDomains; preload", &r)
	if r.HSTSMaxAge != 31536000 || !r.HSTSIncludeSubDomains || !r.HSTSPreload {
		t.Fatalf("got max=%d sub=%v preload=%v", r.HSTSMaxAge, r.HSTSIncludeSubDomains, r.HSTSPreload)
	}
}

func TestDiscoverSubresourcesAndMixedContent(t *testing.T) {
	base, _ := url.Parse("https://example.com/page")
	body := []byte(`<html><body>
<script src="https://cdn.other.com/app.js"></script>
<img src="http://insecure.example/img.png">
</body></html>`)
	refs := discoverSubresources(body, base)
	if len(refs) < 2 {
		t.Fatalf("refs=%#v", refs)
	}
	hits := mixedContentFromRefs(refs)
	if len(hits) == 0 {
		t.Fatal("expected mixed content hit for http:// img")
	}
	hosts := activeHTTPSHosts(refs, "example.com")
	foundCDN := false
	for _, h := range hosts {
		if h == "cdn.other.com" {
			foundCDN = true
		}
	}
	if !foundCDN {
		t.Fatalf("expected cdn.other.com in active hosts, got %v", hosts)
	}
}

func TestRedirectChainFindings(t *testing.T) {
	fs := RedirectChainFindings([]string{
		"http://example.com",
		"https://other.example/",
	}, "", "example.com")
	var hostChange bool
	for _, f := range fs {
		if f.Code == "HTTP-007" {
			hostChange = true
		}
	}
	if !hostChange {
		t.Fatalf("expected HTTP-007, got %#v", fs)
	}
	long := make([]string, 6)
	for i := range long {
		long[i] = "https://example.com/hop"
	}
	fs = RedirectChainFindings(long, "", "example.com")
	var longChain bool
	for _, f := range fs {
		if f.Code == "HTTP-006" {
			longChain = true
		}
	}
	if !longChain {
		t.Fatalf("expected HTTP-006, got %#v", fs)
	}
	fs = RedirectChainFindings(nil, "reset", "example.com")
	if len(fs) != 1 || fs[0].Code != "HTTP-004" {
		t.Fatalf("got %#v", fs)
	}
}
