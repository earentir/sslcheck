# api — `sslcheck api`

Serves **only** `/api/v1/*` (no HTML UI). Use when a reverse proxy terminates TLS and you want a minimal listener.

**Prereqs:** Linux with systemd, `sslcheck` binary built for this arch, outbound HTTPS allowed (scans reach targets).

**Config file:** `/etc/sslcheck/api.env` (path assumed by `sslcheck-api.service`; copy from `default.env`).

| Option | Meaning | Default / example |
|--------|---------|-------------------|
| `LISTEN` | Bind address passed to `--listen`. | `127.0.0.1:8080` in repo file; use `:8080` or `0.0.0.0:8080` to listen on all interfaces. |

**Logging (optional):** The binary supports global flags `--log-file /path` and `--log-level debug|info|warn|error` (stderr banner still applies). The stock unit does not set them; add them to `ExecStart` after `--listen` if you want a log file, e.g. `--log-file /var/log/sslcheck-api.log --log-level info`.

**Deploy**

1. Install binary: `sudo install -m755 sslcheck /usr/local/bin/sslcheck`
2. Config: `sudo mkdir -p /etc/sslcheck && sudo cp default.env /etc/sslcheck/api.env` — edit `LISTEN` if needed.
3. Unit: `sudo cp sslcheck-api.service /etc/systemd/system/`
4. Start: `sudo systemctl daemon-reload && sudo systemctl enable --now sslcheck-api`

**Verify:** `curl -s http://127.0.0.1:8080/api/v1/health` (change host/port to match `LISTEN`). Full route list: **`../API.md`**.
