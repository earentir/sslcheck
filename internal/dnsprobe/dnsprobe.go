package dnsprobe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
)

func ResolveHost(ctx context.Context, host, port string) (model.DNSResult, []model.Finding) {
	start := time.Now()
	var findings []model.Finding
	result := model.DNSResult{Host: host, Port: port}
	logx.Debug("DNS LookupIPAddr", "host", host)

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		logx.Warn("DNS resolution failed", "host", host, "err", err.Error())
		findings = append(findings, model.Finding{
			Code: "DNS-001", Severity: model.SeverityCritical, Title: "DNS resolution failed",
			Description: fmt.Sprintf("Resolver could not resolve %q — no A/AAAA answers usable by the scanner.", host),
			Evidence:    err.Error(),
			Remediation: "Create A/AAAA records at your DNS provider; confirm propagation with dig/nslookup from another network.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Learn_web_development/Howto/Web_mechanics/What_is_a_domain_name",
		})
		result.LookupMS = time.Since(start).Milliseconds()
		return result, findings
	}

	seen := map[string]struct{}{}
	for _, ip := range ips {
		s := ip.IP.String()
		if _, ok := seen[s]; ok { continue }
		seen[s] = struct{}{}
		result.IPs = append(result.IPs, s)
	}
	sort.Strings(result.IPs)
	logx.Debug("DNS A/AAAA", "host", host, "ips", result.IPs)

	if cname, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
		result.CNAME = strings.TrimSuffix(cname, ".")
		logx.Debug("DNS CNAME", "host", host, "cname", result.CNAME)
	} else {
		logx.Debug("DNS CNAME lookup", "host", host, "err", err.Error())
	}
	result.CAARecords = lookupCAA(ctx, host)
	logx.Debug("DNS CAA", "host", host, "records", len(result.CAARecords))
	result.LookupMS = time.Since(start).Milliseconds()

	if len(result.IPs) == 0 {
		findings = append(findings, model.Finding{
			Code: "DNS-002", Severity: model.SeverityCritical, Title: "No A/AAAA records for " + host,
			Description: "Lookup succeeded but produced no IPv4 or IPv6 addresses for this name.",
			Evidence:    fmt.Sprintf("Host %q returned zero IPs after lookup.", host),
			Remediation: "Add at least one A (IPv4) or AAAA (IPv6) record pointing to your origin.",
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Learn_web_development/Howto/Web_mechanics/What_is_a_domain_name",
		})
	} else if len(result.IPs) > 1 {
		findings = append(findings, model.Finding{
			Code: "DNS-003", Severity: model.SeverityInfo, Title: fmt.Sprintf("Multiple IPs for %s", host),
			Description: "Several addresses are published; the scanner will probe each and compare TLS behavior.",
			Evidence:    strings.Join(result.IPs, ", "),
			ReferenceURL: "https://developer.mozilla.org/en-US/docs/Glossary/Load_balancer",
		})
	}

	if len(result.CAARecords) == 0 {
		findings = append(findings, model.Finding{
			Code: "DNS-010", Severity: model.SeverityInfo, Title: "No CAA records for " + host,
			Description: "CAA limits which CAs may issue certs; absence means any CA could issue if they validate control.",
			Evidence:    "CAA query returned no records (or lookup skipped).",
			Remediation: "Publish CAA at DNS e.g. 0 issue \"letsencrypt.org\" for your zone.",
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
		})
	} else {
		var vals []string
		for _, rec := range result.CAARecords {
			vals = append(vals, rec.Tag+"="+rec.Value)
		}
		findings = append(findings, model.Finding{
			Code: "DNS-011", Severity: model.SeverityInfo, Title: "CAA records present",
			Description: "Certificate Authority Authorization records published for this name.",
			Evidence:    strings.Join(vals, ", "),
			ReferenceURL: "https://datatracker.ietf.org/doc/html/rfc8659",
		})
	}

	findings = append(findings, FamilyFindings(result.IPs)...)
	return result, findings
}

func lookupCAA(ctx context.Context, host string) []model.CAARecord {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeCAA)
	client := &dns.Client{}
	in, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(cfg.Servers[0], cfg.Port))
	if err != nil {
		return nil
	}

	var out []model.CAARecord
	for _, ans := range in.Answer {
		caa, ok := ans.(*dns.CAA)
		if !ok { continue }
		out = append(out, model.CAARecord{
			Flag: uint8(caa.Flag), Tag: caa.Tag, Value: caa.Value,
		})
	}
	return out
}
