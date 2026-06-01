package netx

import "time"

// MaxTCPDialTimeout is the maximum time to wait for an IPv4/IPv6 TCP connect.
const MaxTCPDialTimeout = 6 * time.Second

// TCPDialTimeout returns the dial timeout for outbound TCP (HTTPS, TLS probes).
// It is capped at MaxTCPDialTimeout so unreachable hosts fail fast.
func TCPDialTimeout(operationTimeout time.Duration) time.Duration {
	if operationTimeout <= 0 {
		return MaxTCPDialTimeout
	}
	if operationTimeout > MaxTCPDialTimeout {
		return MaxTCPDialTimeout
	}
	return operationTimeout
}
