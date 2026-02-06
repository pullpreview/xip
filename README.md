# xip DNS service

`xip` is an authoritative DNS server for dashed-IP hostnames, intended for pullpreview-style ephemeral environments.

Examples:

- `1-2-3-4-preview.example.test` -> `1.2.3.4`
- `preview-1-2-3-4.example.test` -> `1.2.3.4`

## Tooling

This project uses [`mise`](https://mise.jdx.dev/) to manage Go.

```console
mise install
```

## Build and test

```console
make test
make build
```

Binary output: `dist/xip`

## Development checks

```console
make check-fmt
make lint
make test
```

To auto-run checks before each commit, install pre-commit hooks:

```console
make precommit-install
```

Run them manually:

```console
make precommit-run
```

## Configuration

`xip` accepts CLI flags and environment variables prefixed with `XIP_`.

- CLI flags always take precedence over environment variables.
- If a value is not provided via flags, the corresponding `XIP_*` env var is used.

### Supported options

| Flag | Env var | Default |
| --- | --- | --- |
| `--domain` | `XIP_DOMAIN` | `xip.test` |
| `--root-addresses` | `XIP_ROOT_ADDRESSES` | `127.0.0.1` |
| `--ns-addresses` | `XIP_NS_ADDRESSES` | `127.0.0.1` |
| `--timestamp` | `XIP_TIMESTAMP` | `0` |
| `--ttl` | `XIP_TTL` | `300` |
| `--listen-udp` | `XIP_LISTEN_UDP` (or `XIP_LISTEN`) | `:53` |
| `--listen-tcp` | `XIP_LISTEN_TCP` (or `XIP_LISTEN`) | `:53` |
| `--listen-http` | `XIP_LISTEN_HTTP` | `:80` |
| `--listen-https` | `XIP_LISTEN_HTTPS` | `:443` |
| `--root-redirect-url` | `XIP_ROOT_REDIRECT_URL` | empty (disabled) |
| `--blocklist-path` | `XIP_BLOCKLIST_PATH` | `/etc/xip/blocklist.csv` |
| `--blocklist-reload-interval` | `XIP_BLOCKLIST_RELOAD_INTERVAL` | `60s` |
| `--acme-cache-dir` | `XIP_ACME_CACHE_DIR` | `/etc/xip/acme-cache` |
| `--acme-email` | `XIP_ACME_EMAIL` | empty |

Address lists accept comma or whitespace separators.

## Blocklist CSV

The blocklist file is a CSV with 2 columns:

```csv
fqdn,reason
abusive.preview.example.com,Malware distribution
```

- FQDN matching is exact and case-insensitive.
- DNS `A` requests for blocked FQDNs are answered with root IP(s).
- The file is reloaded from disk every 60 seconds by default.

## HTTP + HTTPS behavior

HTTP server (`--listen-http`) serves:

- `GET /health`: JSON with `blocked_domains` and `last_reload_time`.
- Blocked hostnames: an inlined error page with the block reason and support contact.

For non-blocked hostnames:

- If `--root-redirect-url` is set, requests are redirected there.
- Otherwise the response is `404`.

HTTPS server (`--listen-https`) uses automatic Let's Encrypt certificates via ACME (`autocert`) with on-disk cache at `--acme-cache-dir` (default `/etc/xip/acme-cache`).
Certificate issuance is allowed for any hostname in the configured zone (`--domain` and all subdomains).

Example:

```console
XIP_ROOT_REDIRECT_URL=https://pullpreview.com/?ref=xip
XIP_ACME_CACHE_DIR=/var/lib/xip/acme-cache
```

## OTEL Telemetry

`xip` emits:

- OTEL metric `xip_dns_requests_total` for every DNS request.
- OTEL application logs (bridged from `slog`).

Metric attributes:

- `fqdn`: queried fully-qualified domain name (normalized)
- `domain`: fqdn with the dashed-IP token removed (for example `ip-1-2-3-4.preview.run` -> `preview.run`)

Use standard OTEL env vars, for example:

```console
OTEL_EXPORTER_OTLP_ENDPOINT=ingest.eu.signoz.cloud
OTEL_EXPORTER_OTLP_HEADERS=signoz-ingestion-key=<your-ingestion-key>
```

Signal-specific endpoint overrides are also supported:

- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
- `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`

If endpoint env vars omit a scheme, `xip` defaults them to `https://`.

### Local run example

```console
XIP_DOMAIN=preview.example.com \
XIP_ROOT_ADDRESSES=203.0.113.10 \
XIP_NS_ADDRESSES=203.0.113.10 \
make run
```

## Deploy with systemd

1. Create `config/.env` from `config/.env.example` and edit values.
2. Deploy with:

```console
make deploy
```

Default remote target is `root@xip.preview.run`.

`make deploy` does the following:

- Builds `xip` for `linux/amd64`
- SSHes to the target host
- Uploads binary + systemd unit + logrotate policy + `config/.env`
- Installs binary to `/usr/local/bin/xip`
- Installs service to `/etc/systemd/system/xip.service`
- Installs logrotate config to `/etc/logrotate.d/xip`
- Syncs env file to `/etc/default/xip`
- Ensures `/etc/xip` exists for blocklist + ACME cache
- Ensures `/etc/xip/blocklist.csv` exists
- Ensures `/var/log/xip/xip.log` exists
- Reloads systemd and restarts `xip.service`

Optional deploy overrides:

- `REMOTE_HOST` (default `xip.preview.run`)
- `SSH_USER` (default `root`)
- `SSH_PORT` (default `22`)
- `REMOTE_BIN`, `REMOTE_SYSTEMD_UNIT`, `REMOTE_ENV_FILE`

Verify deployed service health and print recent logs:

```console
make deploy-check
```

Sync only the blocklist CSV (default target `root@xip.preview.run`):

```console
make blocklist
```

Optional blocklist sync overrides:

- `REMOTE_HOST` (default `xip.preview.run`)
- `SSH_USER` / `SSH_PORT`
- `LOCAL_BLOCKLIST_FILE`

## Docker

```console
docker build -t xip .
docker run --rm -p 53:53/udp -p 53:53/tcp -p 80:80 -p 443:443 --env-file config/.env xip
```
