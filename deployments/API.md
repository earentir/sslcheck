# HTTP API (`/api/v1`)

Used by **`sslcheck api`** and **`sslcheck web`** (web also serves non-API pages).

## Routes

| method | path | purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Liveness; JSON includes `scanner_version`, `scanner_source`. |
| GET | `/api/v1/schema` | Report JSON Schema document. |
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
