# sslcheck — TODO

## Report contract (JSON)

**Goal:** every scan report exposes these facts explicitly (stable field names; do not force consumers to infer from findings alone).

1. **`weak_cipher_support`** (string array, per TLS endpoint)  
   Every weak/legacy cipher the server **accepted** during probe. Empty = none accepted.

2. **`ocsp_stapled`** (bool, per TLS endpoint)  
   `true` if the handshake included a stapled OCSP response.

3. **`ocsp_stapled_status`** (string, per TLS endpoint) — **to add**  
   When stapled: `good` / `revoked` / `unknown` / parse error. Today `ocsp_status` exists but stapling vs active OCSP should be obvious in JSON.

4. **HSTS block** (HTTPS result)  
   - **`hsts`**: raw `Strict-Transport-Security`, or empty  
   - **`hsts_max_age`**, **`hsts_include_subdomains`**, **`hsts_preload`**: parsed when present; zero/false when absent  

5. **`caa_records`** (DNS)  
   Flag, tag, value per record. Empty = none returned for this lookup.

6. **`caa_satisfies_scan`** (bool or enum) — **to add**  
   Conclusion: `no_records` | `allows_issuer` | `policy_mismatch` — match leaf issuer/CA against CAA `issue` / `issuewild` (and wildcard hostname rules). Do not equate “CAA present” with “CAA OK”.

7. **`certificate_transparency`** summary — **to add**  
   e.g. `sct_count`, `sct_sources` (embedded vs extension), `ct_compliance` (unknown | likely_ok | failed) after SCT checks.

8. **`revocation`** summary — **to add**  
   Stapled OCSP, active OCSP result, CRL checked (yes/no), overall `revocation_status` for the leaf.

---

## New SSL / TLS / certificate checks (findings)

Already implemented (reference): expiry CERT-010–013, trust CERT-021, hostname CERT-020, weak keys/sig CERT-030–034, chain lint CERT-050–053, TLS versions TLS-010–012, weak ciphers TLS-050, ALPN TLS-020/022, SNI TLS-030–033, active OCSP TLS-080–083, stapling hint TLS-021, multi-IP EDGE-001–004, AIA chain build, etc.

**To add (priority roughly top → bottom):**

### CAA & DNS-TLS
- [ ] **CAA policy vs leaf** — finding when records exist but do not authorize the observed issuer (feeds `caa_satisfies_scan`).
- [ ] **DANE / TLSA** — optional probe: TLSA RRSET vs presented cert (only when TLSA exists).

### Revocation (beyond today)
- [ ] **Must-Staple** (`TLSFeature` / OID) — critical if required but no staple or staple not `good`.
- [ ] **Stapled OCSP validation** — warn/fail on revoked/unknown stapled response (partially parsed today; needs explicit finding).
- [ ] **CRL fetch** — at least one CRL DP fetched and checked (today CERT-042 = “no CRL URLs” only).

### Certificate Transparency
- [ ] **SCT verification** — validate embedded/handshake SCTs against logs (or lightweight “present & plausible”).
- [ ] **CERT-040 follow-up** — distinguish “no SCTs” vs “SCTs invalid / wrong log”.

### Leaf & chain quality
- [ ] **EKU / key usage** — leaf must include `serverAuth`; flag dangerous `any`, encipherment-only, clientAuth-only server certs.
- [ ] **Wildcard SAN** — warn on `*.` coverage issues, depth, cert valid for parent but not requested host.
- [ ] **Intermediate quality** — SHA-1 intermediate, weak RSA intermediate, **expired intermediate** in built chain.
- [ ] **AKI/SKI / name constraints** — broken chain signatures, path length violations (if not already covered by verify).

### TLS hardening probes
- [ ] **TLS 1.3 0-RTT** — detect / warn if early data accepted.
- [ ] **Insecure renegotiation** — probe if offered.
- [ ] **TLS compression** — CRIME (compression enabled).
- [ ] **NULL / export / anon** cipher families — explicit probes beyond current weak list.
- [ ] **Downgrade resistance** — document TLS 1.3 downgrade markers if observable.

### Consistency & edge cases
- [ ] **mTLS** — note if server requests client certificate.
- [ ] **Short-lived cert policy** — info/warn for very short NotAfter without automation signals (optional).
- [ ] **Cross-IP SPKI / pin consistency** — same host, different public keys across IPs (optional, advanced).

### Policy profiles
- [ ] **Strict profile hooks** for new checks (CAA satisfaction, Must-Staple, CT, CRL) where applicable.

---

## Verification (optional later)

Golden JSON or local TLS fixture runs that assert report keys and representative finding codes (e.g. CERT-011, CERT-012, TLS-050) — no external network.
