# sslcheck — TODO

## Report contract (JSON) — done

**Goal:** every scan report exposes these facts explicitly (stable field names; do not force consumers to infer from findings alone).

1. [x] **`weak_cipher_support`** (string array, per TLS endpoint)  
   Every weak/legacy cipher the server **accepted** during probe. Empty = none accepted.

2. [x] **`ocsp_stapled`** (bool, per TLS endpoint)  
   `true` if the handshake included a stapled OCSP response.

3. [x] **`ocsp_stapled_status`** (string, per TLS endpoint)  
   When stapled: `good` / `revoked` / `unknown` / `parse_error`. Legacy `ocsp_status` retained for compatibility.

4. [x] **HSTS block** (HTTPS result)  
   - **`hsts`**: raw `Strict-Transport-Security`, or empty  
   - **`hsts_max_age`**, **`hsts_include_subdomains`**, **`hsts_preload`**: parsed when present; zero/false when absent  

5. [x] **`caa_records`** (DNS)  
   Flag, tag, value per record. Empty = none returned for this lookup.

6. [x] **`caa_satisfies_scan`** (enum)  
   `no_records` | `allows_issuer` | `policy_mismatch` | `unknown_issuer` — match leaf issuer against CAA `issue` / `issuewild`.

7. [x] **`certificate_transparency`** summary  
   `sct_count`, `sct_sources` (embedded vs tls_handshake), `ct_compliance` (`unknown` | `likely_ok` | `failed`).

8. [x] **`revocation`** summary  
   Stapled OCSP, active OCSP result, CRL checked, `must_staple_required`, overall `revocation_status`.

---

## New SSL / TLS / certificate checks (findings) — done

Already implemented (reference): expiry CERT-010–013, trust CERT-021, hostname CERT-020, weak keys/sig CERT-030–034, chain lint CERT-050–053, TLS versions TLS-010–012, weak ciphers TLS-050, ALPN TLS-020/022, SNI TLS-030–033, active OCSP TLS-080–083, stapling hint TLS-021, multi-IP EDGE-001–004, AIA chain build, etc.

### CAA & DNS-TLS
- [x] **CAA policy vs leaf** — DNS-012 when records exist but do not authorize issuer (`caa_satisfies_scan`).
- [x] **DANE / TLSA** — optional probe: TLSA RRSET vs presented cert when TLSA exists (DNS-030–032).

### Revocation (beyond today)
- [x] **Must-Staple** — TLS-085 critical if required but no staple or staple not `good`.
- [x] **Stapled OCSP validation** — TLS-086/TLS-087 on revoked/unknown stapled response.
- [x] **CRL fetch** — TLS-088/TLS-089; CERT-042 when no CRL URLs.

### Certificate Transparency
- [x] **SCT summary** — embedded/handshake SCT presence (`certificate_transparency` block).
- [x] **CERT-040 / CERT-043** — distinguish “no SCTs” vs “embedded SCT extension present”.

### Leaf & chain quality
- [x] **EKU / key usage** — CERT-060–062 (serverAuth, any, encipherment-only).
- [x] **Wildcard SAN** — CERT-063/CERT-064.
- [x] **Intermediate quality** — CERT-054–056 (expired, SHA-1, weak RSA intermediate).

### TLS hardening probes
- [x] **NULL / export / anon** cipher families — TLS-051 via `tls.InsecureCipherSuites()`.
- [ ] **TLS 1.3 0-RTT** — not observable from Go client (see `docs/VERIFICATION.md`).
- [ ] **Insecure renegotiation** — not observable (Go disables renegotiation).
- [ ] **TLS compression** — not observable (Go client disables compression).
- [ ] **Downgrade resistance** — documented only; use protocol_support map.

### Consistency & edge cases
- [ ] **mTLS** — not reliably observable from passive client probe (documented).
- [x] **Short-lived cert policy** — CERT-057 info when NotAfter &lt; 15 days.
- [x] **Cross-IP SPKI consistency** — EDGE-005.

### Policy profiles
- [x] **Strict profile hooks** — POL-003–006 (CAA satisfaction, Must-Staple, CT, CRL).

---

## Verification — done

- [x] Local TLS fixture integration tests (`internal/testtls`, `run_ssl_integration_test.go`, `probe_integration_test.go`, `report_contract_integration_test.go`).
- [x] Documentation: `docs/VERIFICATION.md` (how to run, coverage, limitations).
