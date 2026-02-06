# AGENTS.md

## Purpose
This repository provides `xip`, an authoritative DNS server for PullPreview-style dashed IPv4 hostnames.

## Stack
- Language: Go
- Go toolchain manager: `mise`
- Primary binary: `xip`

## Setup
```bash
mise install
```

## Common Commands
```bash
make test
make build
make build-linux-amd64
make deploy SERVER_IP=<server-ip>
```

## Behavior Requirements
- Keep CLI flags and `XIP_` environment variables in sync.
- CLI flags must take precedence over environment variables.
- Current scope is IPv4 only (`A` records). Do not add IPv6 unless explicitly requested.
- Dashed hostname parsing must remain strict and covered by tests.

## Quality Gate
Before submitting changes, run:
```bash
make check-fmt
make lint
make test
```

## Pre-commit Hooks
This repo includes `.pre-commit-config.yaml`.
Install hooks locally once:
```bash
make precommit-install
```
Run manually on demand:
```bash
make precommit-run
```

## Deployment Notes
`make deploy` expects:
- local `config/.env`
- SSH access to target server

It syncs:
- binary to `/usr/local/bin/xip`
- systemd unit to `/etc/systemd/system/xip.service`
- logrotate policy to `/etc/logrotate.d/xip`
- env file to `/etc/default/xip`
