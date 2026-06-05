package dnsprobe

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
)

// ResolveHostCollect performs DNS lookups without building findings (for agent collect).
func ResolveHostCollect(ctx context.Context, host, port string, opts ResolveOptions, timings *[]model.PhaseTiming) (model.DNSResult, error) {
	start := time.Now()
	result := model.DNSResult{Host: host, Port: port, CAARecords: []model.CAARecord{}, TLSARecords: []model.TLSARecord{}}
	res := ResolverForDNSServer(opts.Server)
	network := strings.TrimSpace(opts.IPNetwork)
	if network != "" && network != "ip4" && network != "ip6" {
		network = ""
	}
	logx.Debug("DNS lookup collect", "host", host, "custom_server", strings.TrimSpace(opts.Server) != "", "ip_network", network)

	tResolve := time.Now()
	var ipList []net.IP
	var err error
	switch network {
	case "ip4", "ip6":
		ipList, err = res.LookupIP(ctx, network, host)
	default:
		var addrs []net.IPAddr
		addrs, err = res.LookupIPAddr(ctx, host)
		if err == nil {
			for _, a := range addrs {
				ipList = append(ipList, a.IP)
			}
		}
	}
	recordPhase(timings, "DNS A/AAAA", tResolve)
	if err != nil {
		logx.Warn("DNS resolution failed", "host", host, "err", err.Error())
		result.LookupMS = time.Since(start).Milliseconds()
		return result, err
	}

	seen := map[string]struct{}{}
	for _, ip := range ipList {
		if ip == nil {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		result.IPs = append(result.IPs, s)
	}
	sort.Strings(result.IPs)
	result.LookupMS = time.Since(tResolve).Milliseconds()

	tCNAME := time.Now()
	cnameCtx, cnameCancel := context.WithTimeout(context.Background(), cnameLookupTimeout)
	result.CNAME = lookupCNAMERecord(cnameCtx, host, normalizeDNSServerAddr(opts.Server))
	cnameCancel()
	recordPhase(timings, "DNS CNAME", tCNAME)

	tCAA := time.Now()
	caaCtx, caaCancel := context.WithTimeout(context.Background(), caaLookupTimeout)
	result.CAARecords = lookupCAA(caaCtx, host, normalizeDNSServerAddr(opts.Server))
	caaCancel()
	recordPhase(timings, "DNS CAA", tCAA)

	tTLSA := time.Now()
	tlsaCtx, tlsaCancel := context.WithTimeout(context.Background(), tlsaLookupTimeout)
	result.TLSARecords = lookupTLSA(tlsaCtx, host, port, normalizeDNSServerAddr(opts.Server))
	tlsaCancel()
	recordPhase(timings, "DNS TLSA", tTLSA)

	result.LookupMS = time.Since(start).Milliseconds()
	return result, nil
}
