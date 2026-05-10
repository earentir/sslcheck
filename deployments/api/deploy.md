# api (`sslcheck api`)

JSON API **only** (no static UI). One process serves **all** routes under `/api/v1/*` — see **`../API.md`**.

**prereqs:** linux, systemd, `sslcheck` binary, egress HTTPS

**config:** `/etc/sslcheck/api.env` — `LISTEN`

**deploy:** `install sslcheck /usr/local/bin/` → `mkdir /etc/sslcheck` → `cp default.env /etc/sslcheck/api.env` → `cp sslcheck-api.service /etc/systemd/system/` → `systemctl daemon-reload enable --now sslcheck-api`

**check:** `curl -s http://127.0.0.1:8080/api/v1/health`
