// Package agentcollect exposes collect/analyze helpers for the networkplane agent.
// Network I/O runs in Collect; cert analysis stays on the sslcheck server.
package agentcollect

import (
	"context"
	"time"

	"sslcheck/internal/model"
	"sslcheck/internal/runner"
)

// Capture is probe output from agent-side collect (JSON-serializable).
type Capture = model.Capture

// Options mirrors runner.Options fields used by the agent.
type Options struct {
	ProfileName    string
	SkipHTTP       bool
	SkipActiveOCSP bool
	FirstIPOnly    bool
	ProxyURL       string
	DNSServer      string
	IPVersion      string
}

// Collect runs DNS/HTTP/TLS probes from the agent and returns capture data.
func Collect(ctx context.Context, rawURL string, timeout time.Duration, opts Options) (*Capture, error) {
	return runner.Collect(ctx, rawURL, timeout, runner.Options{
		ProfileName:    opts.ProfileName,
		SkipHTTP:       opts.SkipHTTP,
		SkipActiveOCSP: opts.SkipActiveOCSP,
		FirstIPOnly:    opts.FirstIPOnly,
		ProxyURL:       opts.ProxyURL,
		DNSServer:      opts.DNSServer,
		IPVersion:      opts.IPVersion,
	})
}
