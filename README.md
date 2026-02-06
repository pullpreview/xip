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

Address lists accept comma or whitespace separators.

## OTEL Metrics

`xip` emits an OTEL counter `xip_dns_requests_total` for every DNS request.

Metric attributes:

- `fqdn`: queried fully-qualified domain name (normalized)
- `domain`: fqdn with the dashed-IP token removed (for example `ip-1-2-3-4.preview.run` -> `preview.run`)

Use standard OTEL env vars, for example:

```console
OTEL_EXPORTER_OTLP_ENDPOINT=ingest.eu.signoz.cloud
OTEL_EXPORTER_OTLP_HEADERS=signoz-ingestion-key=<your-ingestion-key>
```

If `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` omits a scheme, `xip` defaults it to `http://`.

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
make deploy SERVER_IP=203.0.113.10
```

`make deploy` does the following:

- Builds `xip` for `linux/amd64`
- SSHes to the target host
- Uploads binary + systemd unit + logrotate policy + `config/.env`
- Installs binary to `/usr/local/bin/xip`
- Installs service to `/etc/systemd/system/xip.service`
- Installs logrotate config to `/etc/logrotate.d/xip`
- Syncs env file to `/etc/default/xip`
- Ensures `/var/log/xip/xip.log` exists
- Reloads systemd and restarts `xip.service`

Optional deploy overrides:

- `SSH_USER` (default `root`)
- `SSH_PORT` (default `22`)
- `SERVER` (alias of `SERVER_IP`)
- `REMOTE_BIN`, `REMOTE_SYSTEMD_UNIT`, `REMOTE_ENV_FILE`

## Docker

```console
docker build -t xip .
docker run --rm -p 53:53/udp -p 53:53/tcp --env-file config/.env xip
```
