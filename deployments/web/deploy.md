# web (`sslcheck web`)

Same **`/api/v1/*`** API as `api/` plus UI at `/`. Routes: **`../API.md`**.

**prereqs:** linux, systemd, `sslcheck` binary, egress HTTPS

**config:** `/etc/sslcheck/web.env` — `LISTEN` (`8081` here so `api` can use `8080` on one host)

**deploy:** `install sslcheck /usr/local/bin/` → `cp default.env /etc/sslcheck/web.env` → `cp sslcheck-web.service /etc/systemd/system/` → `systemctl daemon-reload enable --now sslcheck-web`

**check:** browser `http://127.0.0.1:8081/` · API `curl http://127.0.0.1:8081/api/v1/health`
