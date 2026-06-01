// Package testtls starts local TLS listeners for integration tests (no external network).
package testtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// Config describes a test TLS endpoint on 127.0.0.1.
type Config struct {
	// Names go on the leaf cert (CN + DNS SANs). Use "127.0.0.1" when probing by IP.
	Names []string
	NotBefore, NotAfter time.Time
	MinVersion, MaxVersion uint16
}

// Endpoint is a running test server.
type Endpoint struct {
	IP, Port string
	Names    []string
}

// Addr returns host:port for URL construction (IP literal).
func (e Endpoint) Addr() string {
	return net.JoinHostPort(e.IP, e.Port)
}

// PrimaryName is the first cert name (SNI / hostname for probes).
func (e Endpoint) PrimaryName() string {
	if len(e.Names) > 0 {
		return e.Names[0]
	}
	return "127.0.0.1"
}

// Start listens on 127.0.0.1:0 and serves TLS. Registers t.Cleanup to close the listener.
func Start(t *testing.T, cfg Config) Endpoint {
	t.Helper()
	if len(cfg.Names) == 0 {
		cfg.Names = []string{"127.0.0.1"}
	}
	if cfg.NotBefore.IsZero() {
		cfg.NotBefore = time.Now().Add(-time.Hour)
	}
	if cfg.NotAfter.IsZero() {
		cfg.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	if cfg.MaxVersion == 0 {
		cfg.MaxVersion = tls.VersionTLS13
	}

	cert, err := leafCert(cfg.Names, cfg.NotBefore, cfg.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   cfg.MinVersion,
		MaxVersion:   cfg.MaxVersion,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return Endpoint{IP: "127.0.0.1", Port: port, Names: append([]string(nil), cfg.Names...)}
}

func leafCert(names []string, notBefore, notAfter time.Time) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(names[0]); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        mustParse(der),
	}, nil
}

func mustParse(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("testtls: %v", err))
	}
	return c
}
