package tlsprobe

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"sslcheck/internal/model"
)

func fetchActiveOCSPResponses(ctx context.Context, chain []*x509.Certificate, httpClient *http.Client) []model.ActiveOCSPCapture {
	if len(chain) < 2 {
		return nil
	}
	leaf := chain[0]
	issuer := chain[1]
	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	var out []model.ActiveOCSPCapture
	for _, ocspURL := range leaf.OCSPServer {
		cap := model.ActiveOCSPCapture{URL: ocspURL}
		reqBody, err := ocsp.CreateRequest(leaf, issuer, nil)
		if err != nil {
			cap.ParseErr = err.Error()
			out = append(out, cap)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(reqBody))
		if err != nil {
			cap.FetchErr = err.Error()
			out = append(out, cap)
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")
		resp, err := client.Do(req)
		if err != nil {
			cap.FetchErr = err.Error()
			out = append(out, cap)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		cap.Body = body
		parsed, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			cap.ParseErr = err.Error()
		} else {
			switch parsed.Status {
			case ocsp.Good:
				cap.Status = "good"
			case ocsp.Revoked:
				cap.Status = "revoked"
			case ocsp.Unknown:
				cap.Status = "unknown"
			default:
				cap.Status = "unknown"
			}
		}
		out = append(out, cap)
	}
	return out
}

func fetchCRLBody(ctx context.Context, chain []*x509.Certificate, httpClient *http.Client) (body []byte, fetchErr string, checked bool, status string) {
	if len(chain) == 0 {
		return nil, "", false, "no_urls"
	}
	leaf := chain[0]
	if len(leaf.CRLDistributionPoints) == 0 {
		return nil, "", false, "no_urls"
	}
	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	for _, u := range leaf.CRLDistributionPoints {
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			fetchErr = err.Error()
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		resp.Body.Close()
		crl, err := x509.ParseRevocationList(b)
		if err != nil {
			fetchErr = err.Error()
			continue
		}
		checked = true
		if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(time.Now()) {
			status = "unreachable"
			return b, "", checked, status
		}
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return b, "", true, "revoked"
			}
		}
		return b, "", true, "good"
	}
	if fetchErr != "" {
		return nil, fetchErr, false, "unreachable"
	}
	return nil, "", false, "unreachable"
}
