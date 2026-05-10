# deployments

sslcheck ships two **long-running modes**: JSON API only, or API plus static UI. Same `/api/v1/*` implementation (`internal/server/mux.go`); **web** adds `/` and static assets.

| folder | starts | binds |
|--------|--------|-------|
| `api/` | `sslcheck api` | `/api/v1/*` only |
| `web/` | `sslcheck web` | `/api/v1/*` + browser UI |

One systemd unit per mode — not one unit per HTTP route. Route list and scan parameters: **`API.md`**.
