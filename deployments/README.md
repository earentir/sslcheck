# deployments

Two **runnable modes** (same codebase):

| folder | command | what listens |
|--------|---------|--------------|
| `api/` | `sslcheck api` | **only** `/api/v1/*` |
| `web/` | `sslcheck web` | **same** `/api/v1/*` plus browser UI at `/` |

There are **no** separate systemd units per HTTP route — one process per mode. All routes: **`API.md`**.
