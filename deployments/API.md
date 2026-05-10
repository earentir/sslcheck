# HTTP API (`/api/v1`)

Same handlers for `sslcheck api` and `sslcheck web` (web adds non-`/api` static files).

| method | path | notes |
|--------|------|-------|
| GET | `/api/v1/health` | liveness + `scanner_version` |
| GET | `/api/v1/schema` | JSON report schema |
| GET | `/api/v1/scan` | query: `url`, `profile`, `timeout_seconds`, `no_http`, `no_active_ocsp`, `first_ip_only`, `proxy_url`, `dns_server`, `ip_version` |
| POST | `/api/v1/scan` | JSON body: same options + `url` |
| OPTIONS | `/api/v1/scan` | CORS preflight: empty 204 |

Registered in `internal/server/mux.go`.
