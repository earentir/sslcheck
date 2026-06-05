package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"sslcheck/internal/logx"
	"sslcheck/internal/model"
	"sslcheck/internal/util"
)

// ProbeEndpointCollect runs TLS/network probes and returns raw capture data (no cert analysis).
func ProbeEndpointCollect(parent context.Context, host, port, ip string, timeout time.Duration, opts Options) model.EndpointCapture {
	network := util.NetworkForIP(ip)
	cap := model.EndpointCapture{
		IP: ip, Network: network, Fast: opts.Fast,
		ProtocolSupport: make(map[string]bool),
	}
	dialer := opts.DialContext

	if opts.Fast {
		return probeEndpointCollectFast(host, port, ip, network, timeout, dialer, opts)
	}

	addr := net.JoinHostPort(ip, port)
	start := time.Now()
	tcpConn, err := dialTCP(dialer, timeout, network, addr)
	if err != nil {
		logx.Warn("TLS TCP failed collect", "host", host, "ip", ip, "err", err.Error())
		cap.TCPDialErr = err.Error()
		return cap
	}
	cap.TCPReachable = true
	cap.TCPConnectLatency = time.Since(start).String()
	_ = tcpConn.Close()

	var bestState tls.ConnectionState
	var rawChain []*x509.Certificate
	var bestErr error

	runParallelTasks(
		func() {
			cap.ProtocolSupport = collectProtocolSupport(parent, host, port, ip, network, timeout, dialer)
			cap.WeakCipherSupport = collectWeakCipherNames(parent, host, port, ip, network, timeout, dialer)
		},
		func() {
			bestState, rawChain, bestErr = probeBestHandshake(parent, host, port, ip, network, timeout, dialer)
		},
	)

	if bestErr != nil {
		cap.HandshakeErr = bestErr.Error()
		tlsErr, ok, cn, sans := collectNoSNI(parent, host, port, ip, network, timeout, dialer)
		cap.TLSErrorNoSNI = tlsErr
		cap.NoSNIHandshakeOK = ok
		cap.NoSNICertCN = cn
		cap.NoSNICertSANs = sans
		return cap
	}

	fillCaptureHandshakeFields(&cap, host, ip, bestState, rawChain, timeout, opts)

	runParallelTasks(
		func() { cap.ALPNProbe = probeALPN(parent, host, port, ip, network, timeout, dialer) },
		func() { cap.Resumption = probeResumption(parent, host, port, ip, network, timeout, dialer) },
		func() { cap.CipherPreference = probeCipherPreference(parent, host, port, ip, network, timeout, dialer) },
		func() {
			outcome, cn := collectWrongSNIOutcome(parent, host, port, ip, network, timeout, dialer)
			cap.WrongSNIOutcome = outcome
			cap.WrongSNIFallbackCN = cn
		},
		func() { cap.SupportedGroups = collectSupportedGroupNames(parent, host, port, ip, network, timeout, dialer) },
	)

	tlsErr, ok, cn, sans := collectNoSNI(parent, host, port, ip, network, timeout, dialer)
	cap.TLSErrorNoSNI = tlsErr
	cap.NoSNIHandshakeOK = ok
	cap.NoSNICertCN = cn
	cap.NoSNICertSANs = sans
	cap.FallbackSCSVAccepted = collectFallbackSCSVAccepted(parent, host, port, ip, network, timeout, cap.ProtocolSupport, dialer)

	return cap
}

func probeEndpointCollectFast(host, port, ip, network string, timeout time.Duration, dialer ContextDialer, opts Options) model.EndpointCapture {
	cap := model.EndpointCapture{
		IP: ip, Network: network, Fast: true,
		ProtocolSupport: make(map[string]bool),
	}
	bestState, rawChain, err := probeBestHandshake(context.Background(), host, port, ip, network, timeout, dialer)
	if err != nil {
		cap.HandshakeErr = err.Error()
		return cap
	}
	cap.TCPReachable = true
	fillCaptureHandshakeFields(&cap, host, ip, bestState, rawChain, timeout, opts)
	cap.ProtocolSupport["TLS1.0"] = bestState.Version == tls.VersionTLS10
	cap.ProtocolSupport["TLS1.1"] = bestState.Version == tls.VersionTLS11
	cap.ProtocolSupport["TLS1.2"] = bestState.Version == tls.VersionTLS12
	cap.ProtocolSupport["TLS1.3"] = bestState.Version == tls.VersionTLS13
	return cap
}
