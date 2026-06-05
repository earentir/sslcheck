package tlsprobe

import (
	"crypto/x509"
	"encoding/base64"
)

func certsToDER(chain []*x509.Certificate) [][]byte {
	if len(chain) == 0 {
		return nil
	}
	out := make([][]byte, len(chain))
	for i, c := range chain {
		if c != nil && len(c.Raw) > 0 {
			out[i] = append([]byte(nil), c.Raw...)
		}
	}
	return out
}

func certsFromDER(blocks [][]byte) []*x509.Certificate {
	var out []*x509.Certificate
	for _, b := range blocks {
		if len(b) == 0 {
			continue
		}
		c, err := x509.ParseCertificate(b)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

func certsDERBase64(chain []*x509.Certificate) []string {
	der := certsToDER(chain)
	out := make([]string, 0, len(der))
	for _, b := range der {
		if len(b) > 0 {
			out = append(out, base64.StdEncoding.EncodeToString(b))
		}
	}
	return out
}

func certsFromDERBase64(blocks []string) []*x509.Certificate {
	raw := make([][]byte, 0, len(blocks))
	for _, s := range blocks {
		if s == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			continue
		}
		raw = append(raw, b)
	}
	return certsFromDER(raw)
}
