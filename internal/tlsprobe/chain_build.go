package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sslcheck/internal/util"
)

// ChainBuildResult holds the resolved certificate chain and how it was obtained.
type ChainBuildResult struct {
	Chain        []*x509.Certificate
	Notes        []string
	FetchedFP    map[string]bool // fingerprints of certs downloaded via AIA
	VerifiedOK   bool            // chain verifies to a system trust anchor
}

// ExtendChainWithAIA walks from the leaf toward the trust anchor, fetching missing
// intermediates (and optionally the root) via AIA Issuing CA URLs until the chain
// verifies against the system trust store or no more certs can be fetched.
// httpClient is used for AIA HTTP(S) fetches; if nil, a default client is used.
func ExtendChainWithAIA(ctx context.Context, host string, peerChain []*x509.Certificate, timeout time.Duration, httpClient *http.Client) ChainBuildResult {
	out := ChainBuildResult{FetchedFP: make(map[string]bool)}
	if len(peerChain) == 0 {
		return out
	}
	var notes []string
	chain := append([]*x509.Certificate(nil), peerChain...)
	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	tryVerify := func(certs []*x509.Certificate) ([]*x509.Certificate, bool) {
		if len(certs) == 0 {
			return nil, false
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			return nil, false
		}
		interm := x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			interm.AddCert(certs[i])
		}
		chains, err := certs[0].Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: interm,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil || len(chains) == 0 {
			return nil, false
		}
		best := chains[0]
		for _, c := range chains[1:] {
			if len(c) < len(best) {
				best = c
			}
		}
		return best, true
	}

	if full, ok := tryVerify(chain); ok {
		out.Chain = full
		out.Notes = notes
		out.VerifiedOK = true
		return out
	}

	seen := certFingerprintSet(chain)

	for attempt := 0; attempt < 8; attempt++ {
		last := chain[len(chain)-1]
		if last.Subject.String() == last.Issuer.String() {
			break
		}
		var fetched *x509.Certificate
		for _, u := range last.IssuingCertificateURL {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			lu := strings.ToLower(u)
			if !strings.HasPrefix(lu, "http://") && !strings.HasPrefix(lu, "https://") {
				continue
			}
			ic, err := fetchCertificate(ctx, client, u)
			if err != nil {
				notes = append(notes, fmt.Sprintf("AIA %s: %v", u, err))
				continue
			}
			fp := certFingerprint(ic)
			if seen[fp] {
				continue
			}
			if err := last.CheckSignatureFrom(ic); err != nil {
				continue
			}
			fetched = ic
			out.FetchedFP[fp] = true
			notes = append(notes, fmt.Sprintf("Fetched issuer via AIA for %s → %s", util.SubjectLine(last), util.SubjectLine(ic)))
			break
		}
		if fetched == nil {
			break
		}
		chain = append(chain, fetched)
		seen[certFingerprint(fetched)] = true

		if full, ok := tryVerify(chain); ok {
			out.Chain = full
			out.Notes = notes
			out.VerifiedOK = true
			return out
		}
	}

	out.Chain = chain
	out.Notes = notes
	out.VerifiedOK = false
	return out
}

func certFingerprintSet(certs []*x509.Certificate) map[string]bool {
	m := make(map[string]bool)
	for _, c := range certs {
		m[certFingerprint(c)] = true
	}
	return m
}

func certFingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

func fetchCertificate(ctx context.Context, client *http.Client, rawURL string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sslcheck/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	// PEM bundle
	var block *pem.Block
	rest := body
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return c, nil
		}
	}
	// Raw DER
	return x509.ParseCertificate(body)
}
