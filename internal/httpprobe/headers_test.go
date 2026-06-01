package httpprobe

import (
	"net/http"
	"testing"
)

func TestAssessHeaders_MissingCSP(t *testing.T) {
	issues := assessHeaders(http.Header{"Server": []string{"nginx"}})
	var csp bool
	for _, hi := range issues {
		if hi.Header == "Content-Security-Policy" {
			csp = true
		}
	}
	if !csp {
		t.Fatalf("expected CSP issue, got %#v", issues)
	}
}

func TestAssessCookies_Insecure(t *testing.T) {
	c := []*http.Cookie{{Name: "sid", Value: "x", Secure: false, HttpOnly: false}}
	issues := assessCookies(c)
	if len(issues) != 1 || len(issues[0].Problems) == 0 {
		t.Fatalf("got %#v", issues)
	}
}
