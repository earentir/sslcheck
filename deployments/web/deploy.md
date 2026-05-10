# web — `sslcheck web`

Same **`/api/v1/*`** as api-only mode, plus the embedded UI at **`/`** (static files; UI POSTs to `/api/v1/scan`). Use when you want the browser form without a separate front-end.

**Prereqs:** Linux with systemd, `sslcheck` binary, outbound HTTPS for scans.

**Config file:** `/etc/sslcheck/web.env` (copy from `default.env`).

| Option | Meaning | Default / example |
|--------|---------|-------------------|
| `LISTEN` | Bind address for API + UI (`--listen`). | `127.0.0.1:8081` here so **`api`** can use **`8080`** on one host; adjust freely. |

**Logging (optional):** Same as api deploy — add `--log-file` / `--log-level` to `ExecStart` in the unit if needed.

**Deploy**

1. `sudo install -m755 sslcheck /usr/local/bin/sslcheck`
2. `sudo mkdir -p /etc/sslcheck && sudo cp default.env /etc/sslcheck/web.env` — edit `LISTEN` if needed.
3. `sudo cp sslcheck-web.service /etc/systemd/system/`
4. `sudo systemctl daemon-reload && sudo systemctl enable --now sslcheck-web`

**Verify:** Open `http://127.0.0.1:8081/` (match `LISTEN`). API: `curl -s http://127.0.0.1:8081/api/v1/health`. Routes: **`../API.md`**.
