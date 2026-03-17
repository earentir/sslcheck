package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/report"
	"sslcheck/internal/runner"
)

// appVersion is the release string (override: -ldflags "-X main.appVersion=1.2.3").
var appVersion = "0.1.102"

const appRepoURL = "https://github.com/earentir/sslcheck"

const validProfiles = "modern, strict"

// appOpts holds all CLI flags (root scan, persistent logging, api/web listen).
type appOpts struct {
	JSONOut, SchemaOut, CSVOut    bool
	Timeout                       time.Duration
	Profile                       string
	NoHTTP, NoActiveOCSP, NoColor bool
	OutputFile                    string
	Quiet, Verbose                bool
	FilePath                      string
	FirstIPOnly                   bool
	ProxyURL                      string
	LogFile, LogLevel             string
	Listen                        string
}

var App appOpts

var rootCmd = &cobra.Command{
	Use:   "sslcheck [flags] [URL ...]",
	Short: "HTTPS / TLS validation scanner",
	Long: `Pure-Go HTTPS / TLS validation scanner.

Project: https://github.com/earentir/sslcheck

Supply one or more https:// URLs unless using --schema.`,
	Args: cobra.ArbitraryArgs,
	RunE: run,
}

func init() {
	fs := rootCmd.Flags()
	fs.BoolVar(&App.JSONOut, "json", false, "emit JSON")
	fs.BoolVar(&App.SchemaOut, "schema", false, "emit JSON schema")
	fs.BoolVar(&App.CSVOut, "csv", false, "emit findings as CSV")
	fs.DurationVar(&App.Timeout, "timeout", 12*time.Second, "per operation timeout")
	fs.StringVar(&App.Profile, "profile", "modern", "policy profile: modern|strict")
	fs.BoolVar(&App.NoHTTP, "no-http", false, "skip HTTP probes")
	fs.BoolVar(&App.NoActiveOCSP, "no-active-ocsp", false, "skip active OCSP URL checks")
	fs.BoolVar(&App.NoColor, "no-color", false, "disable colored output")
	fs.StringVarP(&App.OutputFile, "output", "o", "", "write report to file (default: stdout)")
	fs.BoolVarP(&App.Quiet, "quiet", "q", false, "only print overall result and findings count")
	fs.BoolVarP(&App.Verbose, "verbose", "v", false, "include full redirect chain and extra detail in text output")
	fs.StringVar(&App.FilePath, "file", "", "read URLs from file (one per line, # for comments)")
	fs.BoolVar(&App.FirstIPOnly, "ip", false, "only probe the first resolved IP")
	fs.StringVar(&App.ProxyURL, "proxy", "", "connect via HTTP CONNECT proxy (host:port or URL)")

	rootCmd.Version = appVersion
	rootCmd.SetVersionTemplate("sslcheck {{.Version}}\n" + appRepoURL + "\n")

	p := rootCmd.PersistentFlags()
	p.StringVar(&App.LogFile, "log-file", "", "append structured logs to this path (default level info if --log-level omitted)")
	p.StringVar(&App.LogLevel, "log-level", "", "console+file level: debug, info, warn, error (with --log-file only, file still defaults to info unless set)")

	rootCmd.PersistentPreRunE = func(*cobra.Command, []string) error {
		banner, err := logx.Init(App.LogFile, App.LogLevel)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stderr, banner)
		return nil
	}
}

func main() {
	defer logx.Sync()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(_ *cobra.Command, args []string) error {
	if App.SchemaOut {
		logx.Info("emitting JSON schema", "output_file", App.OutputFile)
		b, err := report.JSONSchema()
		if err != nil {
			return fmt.Errorf("schema: %w", err)
		}
		if App.OutputFile != "" {
			if err := os.WriteFile(App.OutputFile, b, 0o644); err != nil {
				return fmt.Errorf("schema output: %w", err)
			}
			return nil
		}
		fmt.Println(string(b))
		return nil
	}

	if App.Profile != "modern" && App.Profile != "strict" {
		logx.Error("invalid profile", "profile", App.Profile)
		return fmt.Errorf("unknown profile %q; use one of: %s", App.Profile, validProfiles)
	}

	urls := args
	if App.FilePath != "" {
		logx.Info("loading URLs from file", "path", App.FilePath)
		fromFile, err := readURLsFromFile(App.FilePath)
		if err != nil {
			logx.Error("read URL file failed", "path", App.FilePath, "err", err.Error())
			return fmt.Errorf("--file: %w", err)
		}
		logx.Debug("URLs from file", "count", len(fromFile))
		urls = fromFile
	}
	if len(urls) < 1 {
		return fmt.Errorf("at least one URL required (use positional args or --file); use --schema to emit schema or --help for usage")
	}

	logx.Info("scan run starting", "url_count", len(urls), "profile", App.Profile, "timeout", App.Timeout.String(),
		"no_http", App.NoHTTP, "no_active_ocsp", App.NoActiveOCSP, "first_ip_only", App.FirstIPOnly,
		"proxy_set", App.ProxyURL != "", "json", App.JSONOut, "csv", App.CSVOut, "quiet", App.Quiet)

	opts := runner.Options{
		ProfileName:      App.Profile,
		SkipHTTP:         App.NoHTTP,
		SkipActiveOCSP:   App.NoActiveOCSP,
		FirstIPOnly:      App.FirstIPOnly,
		ProxyURL:         App.ProxyURL,
		ScannerVersion:   appVersion,
		ScannerSourceURL: appRepoURL,
	}
	ctx := context.Background()
	var reports []*model.Report
	for i, urlStr := range urls {
		logx.Info("scanning URL", "index", i+1, "total", len(urls), "url", urlStr)
		rep, err := runner.Run(ctx, urlStr, App.Timeout, opts)
		if err != nil {
			logx.Error("scan failed", "url", urlStr, "err", err.Error())
			return fmt.Errorf("%s: %w", urlStr, err)
		}
		logx.Info("scan finished", "url", urlStr, "overall", rep.Overall, "findings", len(rep.Findings), "duration_ms", rep.DurationMS)
		reports = append(reports, rep)
	}

	out := os.Stdout
	if App.OutputFile != "" {
		logx.Debug("writing report to file", "path", App.OutputFile)
		f, err := os.Create(App.OutputFile)
		if err != nil {
			logx.Error("create output file failed", "path", App.OutputFile, "err", err.Error())
			return fmt.Errorf("output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	if App.JSONOut {
		logx.Debug("encoding JSON report", "reports", len(reports))
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if len(reports) == 1 {
			return enc.Encode(reports[0])
		}
		return enc.Encode(reports)
	}

	if App.CSVOut {
		return report.CSV(out, reports)
	}

	useColor := report.ShouldUseColor(App.NoColor, out)
	if App.Quiet {
		for i, rep := range reports {
			fmt.Fprint(out, report.QuietSummary(rep, useColor))
			if i < len(reports)-1 {
				fmt.Fprintln(out)
			}
		}
		return nil
	}

	for i, rep := range reports {
		if i > 0 {
			fmt.Fprintf(out, "\n---\n\n")
		}
		fmt.Fprint(out, report.Render(rep, useColor, App.Verbose))
	}
	return nil
}

func readURLsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}
