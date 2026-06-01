# Verification (integration tests)

Functional SSL checks run against **local TLS fixtures** — no external network required.

## Run integration tests only

From the repo root:

```bash
make
go test ./internal/runner/ -run 'LocalTLS|ReportContract' -count=1 -timeout 120s
go test ./internal/tlsprobe/ -run LocalServer -count=1 -timeout 120s
```

Do **not** need `go test ./...` unless you want the full suite (includes small unit tests elsewhere).

## What is covered

| Test file | What it validates |
|-----------|-------------------|
| `internal/runner/run_ssl_integration_test.go` | Full scan pipeline: DNS → TLS → findings (`CERT-011`, `CERT-012`, IPv4-only) |
| `internal/runner/report_contract_integration_test.go` | JSON report contract keys: `caa_satisfies_scan`, `ocsp_stapled_status`, `certificate_transparency`, `revocation`, `phase_timings` |
| `internal/tlsprobe/probe_integration_test.go` | TLS probe in isolation: handshake, expiry, hostname mismatch, legacy TLS |

Fixtures live in `internal/testtls/` — ephemeral `127.0.0.1` listeners with generated certs.

## Manual smoke (optional, uses network)

```bash
./bin/sslcheck --debug --json https://example.com | jq '.dns.caa_satisfies_scan, .endpoints[0].revocation, .endpoints[0].certificate_transparency'
```

## Probe limitations (documented)

These are **not** fully observable from a Go TLS client probe today; findings or JSON fields may be absent:

| Check | Status |
|-------|--------|
| TLS 1.3 0-RTT early data | Not probed (requires custom ClientHello early-data) |
| TLS compression (CRIME) | Go client disables compression; cannot detect server offer |
| Insecure renegotiation | Renegotiation disabled in Go TLS stack |
| mTLS (client cert requested) | Rarely exposed on first handshake without server-specific behavior |
| Full SCT log verification | Lightweight: `sct_count`, `sct_sources`, `ct_compliance` only |
| TLS 1.3 downgrade markers | Document only; inferred from protocol_support map |

## Report contract reference

See `TODO.md` (completed section) and `--schema` / `GET /api/v1/schema` for field names.

Key endpoint fields:

- `weak_cipher_support` — array of accepted weak/insecure cipher names
- `ocsp_stapled` / `ocsp_stapled_status` — stapling presence and parsed status
- `certificate_transparency` — `{ sct_count, sct_sources, ct_compliance }`
- `revocation` — `{ stapled_ocsp, stapled_ocsp_status, active_ocsp_status, crl_checked, crl_status, must_staple_required, revocation_status }`

DNS fields:

- `caa_records` — `{ flag, tag, value }[]`
- `caa_satisfies_scan` — `no_records` \| `allows_issuer` \| `policy_mismatch` \| `unknown_issuer`
- `tlsa_records` — DANE TLSA when present
