# sslcheck

Pure-Go HTTPS / TLS validation scanner.

## Run

```bash
go mod tidy
go run . https://example.com
go run . --json https://example.com
go run . --schema
```

## Building

```bash
go build -o sslcheck .
```

To embed a version at build time:

```bash
go build -ldflags "-X main.appVersion=1.0.0" -o sslcheck .
```

Default is the `appVersion` var at the top of `main.go`.

Integration / fixture tests (no external network): see [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Usage

```
sslcheck [flags] [URL ...]
```

Supply one or more targets per run: full `https://` URLs, `http://` (normalized to HTTPS for the scan), or a bare hostname like `earentir.dev` (HTTPS is assumed). Use `--file` to read lines from a file (`#` comments). Use `--schema` for the JSON schema only.

### Logging (`--log-file`, `--log-level`)

Structured logs go to **stderr** and optionally to a file. On startup, one line is always printed to stderr, e.g. `sslcheck logging: level=info console=stderr file=/path/to/sslcheck.log`.

| Flags | Behavior |
|-------|----------|
| *(none)* | Console only, **warn** and above. No log file. |
| `--log-file PATH` | Append to `PATH` at **info** (file + console). Omit `--log-level` → both use **info**. |
| `--log-level debug\|info\|warn\|error` | Console at that level; append to **`sslcheck.log` next to the binary** (same level). If that path is not writable, falls back to `./sslcheck.log`. |
| Both | Console and file at `--log-level`; file is `--log-file`. |

`--json` / report output stays on **stdout**; logs stay on **stderr** so pipelines stay clean.

Subcommands:

| Command | Description |
|---------|-------------|
| `sslcheck api` | HTTP **API only** (JSON). Use behind nginx; no TLS in-process. |
| `sslcheck web` | Same API **plus** a small browser UI at `/`. |

### HTTP API (`sslcheck api`)

Listen address: `--listen` (default `:8080`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | `{"status":"ok","scanner_version":"…","scanner_source":"https://github.com/earentir/sslcheck"}` |
| GET | `/api/v1/schema` | JSON schema for reports |
| GET | `/api/v1/checks` | List all supported finding codes (summary) |
| GET | `/api/v1/checks/{code}` | Full metadata for one finding code (e.g. `CERT-011`) |
| GET | `/api/v1/scan?url=https://...` | Run scan (optional: `profile`, `timeout_seconds`, `no_http`, `no_active_ocsp`, `first_ip_only`, `proxy_url`) |
| POST | `/api/v1/scan` | Body: `{"url":"earentir.dev"}` or full URL — same rules as CLI |

Errors: `400` with `{"error":"..."}`.

### Web UI (`sslcheck web`)

Serves the API under `/api/v1/*` and a single-page UI at `/` (redirects to `index.html`). The page POSTs to `/api/v1/scan` on the same origin.

### nginx (TLS termination in front)

Both commands speak plain HTTP. Example:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_read_timeout 130s;
    proxy_connect_timeout 10s;
}
```

### Flags

| Flag | Short | Description |
|------|--------|-------------|
| `--json` | | Emit report as JSON |
| `--schema` | | Emit JSON schema and exit |
| `--csv` | | Emit findings as CSV |
| `--timeout` | | Per-operation timeout (default 12s) |
| `--profile` | | Policy profile: `modern` or `strict` (default modern) |
| `--no-http` | | Skip HTTP redirect and application probes |
| `--no-active-ocsp` | | Skip active OCSP responder checks |
| `--no-color` | | Disable colored output |
| `--output` | `-o` | Write report to file |
| `--quiet` | `-q` | Only print overall result, grade, and findings count |
| `--verbose` | `-v` | Include full redirect chain and extra detail |
| `--file` | | Read URLs from file (one per line, # comments) |
| `--ip` | | Only probe the first resolved IP |
| `--proxy` | | Connect via HTTP CONNECT proxy (host:port or URL) |
| `--version` | | Print version and project URL (Cobra default; `-v` is `--verbose`) |

Colored output is enabled when stdout is a terminal and `NO_COLOR` is not set. Use `--no-color` to force plain output.

### Exit codes

- **0** — Success (schema printed or check completed)
- **1** — Error (e.g. invalid URL, run failure, schema generation failed)
- **2** — Usage / validation error (e.g. unknown profile, missing URL)

## Current capabilities

- URL normalization
- DNS resolution, CAA lookup, IPv4 / IPv6 findings
- TCP reachability
- TLS protocol support probing
- Weak cipher probing (e.g. 3DES, RSA CBC)
- TLS fallback SCSV check (RFC 7507)
- Certificate inspection and trust checks; full chain (leaf → intermediates → root) at the top of the report with days to expiry per cert
- Missing intermediates resolved via AIA (HTTP) when possible, labeled as **fetched via AIA** vs **sent by server** vs **trust anchor**
- OCSP stapling decode and active OCSP checks
- ALPN probing, session resumption, no-SNI / wrong-SNI probing
- Key exchange group probing, TLS 1.2 cipher preference
- HTTP redirect and redirect chain analysis
- HSTS, cookie security, and header policy checks (including HPKP deprecated notice)
- Mixed-content detection and active HTTPS subresource host TLS checks
- Cross-edge consistency findings
- JSON and CSV output, JSON schema
- Optional letter grade (A+–F) and colored text output

## Scope and comparison

sslcheck focuses on configuration and compliance checks that can be done with standard TLS and HTTP. It does **not** implement custom vulnerability probes such as Heartbleed, POODLE, DROWN, BEAST, or CRIME; for those, consider [testssl.sh](https://github.com/drwetter/testssl.sh) or the [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) server test. sslcheck is suitable for local or CI use, single or batch URLs, and scripted reporting (JSON/CSV).

## Notes

- `HSTS max-age=0` is treated as a warning, not a failure.
- Active HTTPS subresource hosts are validated separately so the tool can catch cases where the main page is trusted but scripts/iframes from another HTTPS origin have certificate errors.
