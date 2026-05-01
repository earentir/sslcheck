# sslcheck — report contract (TODO)

**Goal:** every scan’s JSON report must clearly expose the facts below (use these names in the model / JSON so nothing is ambiguous).

1. **`weak_cipher_support`** (string array, per TLS endpoint)  
   List every weak/legacy cipher suite the server accepted during the probe. Empty array = none accepted. Downstream uses this as “any weak cipher offered: yes/no”.

2. **`ocsp_stapled`** (bool, per TLS endpoint)  
   `true` if the TLS handshake included a stapled OCSP response; `false` if not.

3. **HSTS block** (HTTPS result)  
   - **`hsts`**: raw `Strict-Transport-Security` header value, or empty if absent.  
   - **`hsts_max_age`**, **`hsts_include_subdomains`**, **`hsts_preload`**: parsed from that header when present; zeros/false when absent.

4. **`caa_records`** (array under DNS for the scanned name)  
   Each record: flag, tag, value (and any other fields you already emit). Empty = no CAA returned for that lookup.

5. **`caa_satisfies_scan` (or similar) — to add**  
   One explicit bool (or a dedicated finding): “CAA, as seen by this scan, allows issuance like the leaf cert you got” vs “records present but policy mismatch” vs “no records”. Today people infer too much from “array non-empty”; the report should say the conclusion in one field.

**Tests TODO:** golden JSON (or handler tests) that run a fixed stub/server or fixture and assert the above keys are present and match expected values.
