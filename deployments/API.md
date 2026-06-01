# HTTP API (`/api/v1`)

Used by **`sslcheck api`** and **`sslcheck web`** (web also serves non-API pages).

## Routes

| method | path | purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Liveness; JSON includes `scanner_version`, `scanner_source`. |
| GET | `/api/v1/schema` | Report JSON Schema document. |
| GET | `/api/v1/checks` | All supported finding codes (summary list). |
| GET | `/api/v1/checks/{code}` | Catalog detail for one code (e.g. `CERT-011`). Case-insensitive. |
| GET | `/api/v1/scan` | Run scan; options as **query** parameters (below). |
| POST | `/api/v1/scan` | Run scan; JSON body with same fields as GET query. |
| OPTIONS | `/api/v1/scan` | Empty `204` for CORS preflight. |

## Scan request parameters

All optional except **`url`** (required).

| field | meaning | default / example |
|-------|---------|-------------------|
| `url` | Target `https://…` or hostname | — required |
| `profile` | Policy: `modern` or `strict` | default `modern` |
| `timeout_seconds` | Scan budget | default **12**; clamped **5–120** |
| `no_http` | Skip HTTP probes | `false`; use `1` / `true` in query |
| `no_active_ocsp` | Skip live OCSP POSTs | `false` |
| `first_ip_only` | TLS only first resolved IP | `false` |
| `proxy_url` | HTTP CONNECT proxy | empty |
| `dns_server` | Recursive resolver (IP or `host:port`) | empty → OS resolver |
| `ip_version` | `4` or `6` only | empty → both families |

Registered in `internal/server/mux.go`; defaults enforced in `internal/server/scan.go`.

## Checks catalog

### `GET /api/v1/checks`

Returns every supported finding code (stable catalog, not scan results):

```json
{
  "count": 103,
  "checks": [
    {
      "code": "CERT-001",
      "category": "CERT",
      "title": "No certificate presented",
      "severity": "critical"
    }
  ]
}
```

### `GET /api/v1/checks/{code}`

Returns full metadata for one code. `{code}` is case-insensitive (`cert-011` = `CERT-011`).

```json
{
  "code": "CERT-011",
  "category": "CERT",
  "title": "Certificate expired",
  "severity": "critical",
  "description": "NotAfter is in the past—browsers show certificate errors.",
  "remediation": "Issue a new cert and reload TLS; automate renewal (ACME etc.).",
  "reference_url": "https://letsencrypt.org/getting-started/"
}
```

`404` + `{"error":"unknown check code: …"}` when the code is not in the catalog.
