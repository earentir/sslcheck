package dnsprobe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"sslcheck/internal/model"
)

const tlsaLookupTimeout = 2 * time.Second

// lookupTLSA queries _443._tcp.<host> TLSA records when present.
func lookupTLSA(ctx context.Context, host, port, customServerHostPort string) []model.TLSARecord {
	if strings.TrimSpace(port) == "" {
		port = "443"
	}
	name := fmt.Sprintf("_%s._tcp.%s", port, host)
	serverAddr := dnsServerAddr(customServerHostPort)
	if serverAddr == "" {
		return nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
	client := &dns.Client{Timeout: tlsaLookupTimeout}
	in, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err != nil || in == nil {
		return nil
	}
	var out []model.TLSARecord
	for _, ans := range in.Answer {
		tlsa, ok := ans.(*dns.TLSA)
		if !ok {
			continue
		}
		out = append(out, model.TLSARecord{
			Usage:        tlsa.Usage,
			Selector:     tlsa.Selector,
			MatchingType: tlsa.MatchingType,
			Certificate:  strings.ToLower(tlsa.Certificate),
		})
	}
	return out
}

// TLSAFindings reports DANE/TLSA mismatches when TLSA exists and TLS succeeded.
func TLSAFindings(host string, records []model.TLSARecord, spkiSHA256, certSHA256 string, tlsOK bool) []model.Finding {
	if len(records) == 0 || !tlsOK {
		return nil
	}
	if spkiSHA256 == "" && certSHA256 == "" {
		return []model.Finding{{
			Code: "DNS-030", Severity: model.SeverityMedium, Title: "TLSA records present but cert digest unavailable",
			Description: "TLSA RRSET exists for this service but the scanner could not compare presented certificate data.",
			Evidence: fmt.Sprintf("_443._tcp.%s has %d TLSA record(s)", host, len(records)),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6698",
		}}
	}
	for _, rec := range records {
		want := strings.ToLower(rec.Certificate)
		var got string
		switch rec.Selector {
		case 0:
			got = certSHA256
		case 1:
			got = spkiSHA256
		default:
			continue
		}
		if got == "" {
			continue
		}
		if rec.MatchingType == 1 && want == got {
			return []model.Finding{{
				Code: "DNS-031", Severity: model.SeverityInfo, Title: "TLSA matches presented certificate",
				Description: "At least one TLSA record matches the observed certificate data.",
				Evidence: fmt.Sprintf("usage=%d selector=%d", rec.Usage, rec.Selector),
				ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6698",
			}}
		}
	}
	return []model.Finding{{
		Code: "DNS-032", Severity: model.SeverityHigh, Title: "TLSA policy mismatch",
		Description: "TLSA records exist but none match the certificate presented during TLS.",
		Evidence: fmt.Sprintf("_443._tcp.%s · %d TLSA record(s)", host, len(records)),
		Remediation: "Update TLSA at DNS or deploy the certificate matching published TLSA.",
		ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc6698",
	}}
}

// TLSAOwnerName returns the TLSA owner name used for lookups.
func TLSAOwnerName(host, port string) string {
	if port == "" {
		port = "443"
	}
	return fmt.Sprintf("_%s._tcp.%s", port, host)
}
