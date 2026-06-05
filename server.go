package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"sslcheck/internal/logx"
	"sslcheck/internal/server"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Serve HTTP JSON API only (for reverse proxy)",
	Long: `Listen for HTTP requests and expose:

  GET  /api/v1/health          — liveness (+ scanner_version, scanner_source)
  GET  /api/v1/schema          — JSON report schema
  GET  /api/v1/checks          — list supported finding codes
  GET  /api/v1/checks/{code}   — catalog detail for one code (e.g. CERT-011)
  GET  /api/v1/scan?url=...    — run scan (query: profile, timeout_seconds, no_http, no_active_ocsp, first_ip_only, proxy_url, dns_server, ip_version)
  POST /api/v1/scan            — JSON body: {"url":"https://...","dns_server":"1.1.1.1","ip_version":"4",...}
  POST /api/v1/analyze         — JSON body: {"url":"https://...","capture":{...}} (agent-collected probes; no target dial)

Project: https://github.com/earentir/sslcheck

Designed to sit behind nginx or another reverse proxy; no TLS in-process.`,
	RunE: runAPI,
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Serve API plus browser UI (for reverse proxy)",
	Long: `Same API as 'sslcheck api', plus a static UI at / for submitting URLs and viewing results.
The UI calls POST /api/v1/scan on the same origin.

Project: https://github.com/earentir/sslcheck`,
	RunE: runWeb,
}

func init() {
	apiCmd.Version = appVersion
	webCmd.Version = appVersion
	const listenUsage = "listen address (e.g. :8080 or 127.0.0.1:9090)"
	apiCmd.Flags().StringVar(&App.Listen, "listen", ":8080", listenUsage)
	webCmd.Flags().StringVar(&App.Listen, "listen", ":8080", listenUsage)
	apiCmd.SilenceUsage = true
	webCmd.SilenceUsage = true
	rootCmd.AddCommand(apiCmd, webCmd)
}

func runAPI(cmd *cobra.Command, args []string) error {
	server.SetScannerMeta(appVersion, appRepoURL)
	logx.Info("starting API server", "listen", App.Listen)
	printListenURLs("api", "/api/v1/health")
	if err := server.ListenAndServe(App.Listen, server.APIOnly()); err != nil {
		logx.Error("API server exited", "listen", App.Listen, "err", err.Error())
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

func runWeb(cmd *cobra.Command, args []string) error {
	server.SetScannerMeta(appVersion, appRepoURL)
	logx.Info("starting web server", "listen", App.Listen)
	printListenURLs("web", "/")
	if err := server.ListenAndServe(App.Listen, server.Web(server.WebUIFS())); err != nil {
		logx.Error("web server exited", "listen", App.Listen, "err", err.Error())
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

func printListenURLs(mode, pathSuffix string) {
	host, port, err := parseListenAddr(App.Listen)
	if err != nil {
		logx.Warn("could not parse listen address for URL list", "mode", mode, "listen", App.Listen, "err", err.Error())
		fmt.Fprintf(os.Stderr, "sslcheck %s listening on %s\n", mode, App.Listen)
		return
	}
	if pathSuffix != "/" && !strings.HasPrefix(pathSuffix, "/") {
		pathSuffix = "/" + pathSuffix
	}
	urls := orderClickableURLs(listenBaseURLs(host, port))
	logx.Info("server listen URLs", "mode", mode, "listen", App.Listen, "bases", len(urls))
	for _, base := range urls {
		logx.Debug("clickable URL", "mode", mode, "url", base+pathSuffix)
		fmt.Fprintln(os.Stdout, "  "+base+pathSuffix)
	}
}

func parseListenAddr(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err == nil {
		return host, port, nil
	}
	if strings.HasPrefix(addr, ":") {
		p := strings.TrimPrefix(addr, ":")
		if p == "" {
			return "", "", fmt.Errorf("missing port in %q", addr)
		}
		return "", p, nil
	}
	return "", "", err
}

// listenBaseURLs returns full http://host:port bases for each address the server binds to.
func listenBaseURLs(bindHost, port string) []string {
	seen := make(map[string]struct{})
	var bases []string
	add := func(host string) {
		h := hostForURL(host)
		if h == "" {
			return
		}
		key := h + ":" + port
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		bases = append(bases, "http://"+key)
	}

	switch {
	case bindHost == "" || bindHost == "0.0.0.0":
		add("127.0.0.1")
		add("localhost")
		for _, ip := range nonLoopbackIPs() {
			add(ip)
		}
	case bindHost == "::" || bindHost == "[::]":
		add("127.0.0.1")
		add("localhost")
		add("::1")
		for _, ip := range nonLoopbackIPs() {
			add(ip)
		}
	default:
		add(bindHost)
	}

	return bases
}

func orderClickableURLs(bases []string) []string {
	var local, other []string
	for _, b := range bases {
		if strings.Contains(b, "127.0.0.1") || strings.Contains(b, "localhost") || strings.Contains(b, "[::1]") {
			local = append(local, b)
		} else {
			other = append(other, b)
		}
	}
	sort.Strings(local)
	sort.Strings(other)
	return append(local, other...)
}

func hostForURL(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func nonLoopbackIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
