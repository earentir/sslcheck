package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"sslcheck/internal/model"
	"sslcheck/internal/util"
)

func collectProtocolSupport(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) map[string]bool {
	_ = parent
	out := map[string]bool{
		"TLS1.0": false, "TLS1.1": false, "TLS1.2": false, "TLS1.3": false,
	}
	versions := []struct {
		Name string
		ID   uint16
	}{
		{"TLS1.0", tls.VersionTLS10}, {"TLS1.1", tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12}, {"TLS1.3", tls.VersionTLS13},
	}
	for _, v := range versions {
		out[v.Name] = tryTLSVersion(parent, host, port, ip, network, timeout, v.ID, dialer)
	}
	return out
}

func collectWeakCipherNames(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) []string {
	_ = parent
	var names []string
	for _, tc := range weakCipherTests {
		if trySpecificCipher(parent, host, port, ip, network, timeout, tc.ID, tc.Version, dialer) {
			names = append(names, tc.Name)
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if trySpecificCipher(parent, host, port, ip, network, timeout, cs.ID, tls.VersionTLS12, dialer) {
			names = append(names, cs.Name)
		}
	}
	return names
}

func collectSupportedGroupNames(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) []string {
	_ = parent
	tests := []struct {
		Name  string
		Group tls.CurveID
	}{
		{"X25519", tls.X25519},
		{"P-256", tls.CurveP256},
		{"P-384", tls.CurveP384},
	}
	var names []string
	for _, tc := range tests {
		ok, err := tryCurve(parent, host, port, ip, network, timeout, tc.Group, dialer)
		if err == nil && ok {
			names = append(names, tc.Name)
		}
	}
	return names
}

func collectWrongSNIOutcome(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) (outcome, fallbackCN string) {
	_ = parent
	badName := "wrong-sni.invalid"
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil {
		return "", ""
	}
	defer rawConn.Close()
	cfg := &tls.Config{
		ServerName: badName, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return "rejected", ""
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", ""
	}
	leaf := state.PeerCertificates[0]
	if err := leaf.VerifyHostname(host); err == nil {
		return "same_cert", leaf.Subject.CommonName
	}
	return "fallback_cert", leaf.Subject.CommonName
}

func collectFallbackSCSVAccepted(parent context.Context, host, port, ip, network string, timeout time.Duration, protocolSupport map[string]bool, dialer ContextDialer) bool {
	_ = parent
	if protocolSupport == nil || !protocolSupport["TLS1.3"] {
		return false
	}
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil {
		return false
	}
	defer rawConn.Close()
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_FALLBACK_SCSV, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		NextProtos:         []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn.Handshake() == nil
}

func collectNoSNI(parent context.Context, host, port, ip, network string, timeout time.Duration, dialer ContextDialer) (tlsErr string, ok bool, cn string, sans []string) {
	_ = parent
	addr := net.JoinHostPort(ip, port)
	rawConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil {
		return err.Error(), false, "", nil
	}
	defer rawConn.Close()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"},
	}
	conn := tls.Client(rawConn, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return err.Error(), false, "", nil
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cn = state.PeerCertificates[0].Subject.CommonName
		sans = append([]string(nil), state.PeerCertificates[0].DNSNames...)
	}
	return "", true, cn, sans
}

func fillCaptureHandshakeFields(cap *model.EndpointCapture, host, ip string, bestState tls.ConnectionState, rawChain []*x509.Certificate, timeout time.Duration, opts Options) {
	cap.TLSHandshakeOK = true
	cap.TLSVersion = util.TLSVersionString(bestState.Version)
	cap.TLSVersionID = bestState.Version
	cap.CipherSuite = tls.CipherSuiteName(bestState.CipherSuite)
	cap.CipherSuiteID = bestState.CipherSuite
	cap.ServerName = bestState.ServerName
	cap.ALPN = bestState.NegotiatedProtocol
	cap.PeerCertCount = len(bestState.PeerCertificates)
	cap.OCSPStapledResponse = append([]byte(nil), bestState.OCSPResponse...)
	cap.SCTCount = len(bestState.SignedCertificateTimestamps)
	cap.PeerCertsDER = certsToDER(rawChain)

	aiaCtx, aiaCancel := probeContext(timeout)
	chainBuild := ExtendChainWithAIA(aiaCtx, host, rawChain, timeout, opts.FetchHTTP)
	aiaCancel()
	cap.FullChainDER = certsToDER(chainBuild.Chain)
	cap.ChainBuildNotes = append([]string(nil), chainBuild.Notes...)
	cap.ChainFetchedFP = chainBuild.FetchedFP
	cap.ChainVerifiedOK = chainBuild.VerifiedOK

	fullChain := chainBuild.Chain
	if !opts.SkipActiveOCSP && len(fullChain) > 0 {
		cap.ActiveOCSP = fetchActiveOCSPResponses(context.Background(), fullChain, opts.FetchHTTP)
	}
	if len(fullChain) > 0 {
		crlCtx, crlCancel := probeContext(timeout)
		body, ferr, checked, status := fetchCRLBody(crlCtx, fullChain, opts.FetchHTTP)
		crlCancel()
		cap.CRLBody = body
		cap.CRLFetchErr = ferr
		cap.CRLChecked = checked
		cap.CRLStatus = status
	}
}
