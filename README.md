[Türkçe](README.tr.md)

# hookprobe

A small, zero-dependency Go CLI for **signing**, **verifying**, **capturing**, and **replaying** webhooks.

`hookprobe` speaks the signature schemes used by **GitHub**, **Stripe**, and **Slack**, plus a generic HMAC mode (SHA-1 / SHA-256 / SHA-512, hex or Base64). It is intended for local development: confirm that your secret and payload produce the expected header, stand up a temporary listener that records deliveries, and replay a saved capture against a service running on your machine.

## Why this exists

Webhook signature bugs are tedious to debug. The payload looks fine, the header looks fine, and the verifier still returns 401 — often because of a missing timestamp, the wrong signed string, or a stale clock window. `hookprobe` makes those checks explicit and scriptable, without pulling in an SDK or any third-party module. Everything is implemented on the Go standard library.

## Features

- Sign and verify GitHub (`X-Hub-Signature-256` / `X-Hub-Signature`), Stripe (`Stripe-Signature` with `t=` / `v1=` and secret rotation), Slack (`v0=` + `X-Slack-Request-Timestamp`), and generic HMAC digests
- Constant-time comparison (`crypto/hmac.Equal`) and a configurable timestamp tolerance (default 5 minutes; pass a negative duration to disable the check)
- `listen` starts a local capture server, auto-detects the provider from headers, optionally forwards to another URL, and writes pretty-printed JSON captures to disk
- `replay` resends a capture as-is, or **re-signs** it with a fresh timestamp so Stripe/Slack still accept older recordings
- Secrets can be passed with `--secret`, `--secret-env VAR`, or the `HOOKPROBE_SECRET` environment variable
- `--json` output on `sign`, `verify`, and `replay` for use in scripts
- No third-party dependencies

## Requirements

- Go 1.22 or later

## Install

```bash
git clone https://github.com/yilmazmurad/hookprobe.git
cd hookprobe
go build -o hookprobe ./cmd/hookprobe
```

To install into your `GOPATH`/`GOBIN`:

```bash
go install github.com/yilmazmurad/hookprobe/cmd/hookprobe@latest
```

## Usage

```text
hookprobe <command> [flags]

Commands:
  sign      Create a signature header for a payload
  verify    Verify a signature or request header against a payload
  listen    Start a local capture server that verifies incoming webhooks
  replay    Replay a saved capture to a target URL
  version   Print the hookprobe version
  help      Show help
```

### Sign a payload

```bash
hookprobe sign --provider github --secret "$HOOK_SECRET" --payload body.json
# sha256=...

hookprobe sign --provider stripe --secret "$HOOK_SECRET" --payload body.json --timestamp 1700000000
# t=1700000000,v1=...

hookprobe sign --provider slack --secret "$HOOK_SECRET" --payload body.json --timestamp 1700000000
# v0=...   (stderr also prints X-Slack-Request-Timestamp)
```

`--payload -` (or omitting `--payload`) reads the body from stdin:

```bash
printf '{"ok":true}' | hookprobe sign --provider generic --secret "$HOOK_SECRET" --algo sha256 --encoding hex
```

### Verify a signature

```bash
hookprobe verify --provider github --secret "$HOOK_SECRET" --payload body.json --signature "sha256=..."
hookprobe verify --provider stripe --secret "$HOOK_SECRET" --payload body.json --header "t=1700000000,v1=..." --timestamp 1700000000
hookprobe verify --provider slack --secret "$HOOK_SECRET" --payload body.json \
  --signature "v0=..." --timestamp-header 1700000000
```

Use `--json` to get a machine-readable result. The process exits `0` when the signature is valid and `1` when it is not.

`--tolerance 5m` is the default window for Stripe and Slack. `--tolerance -1s` skips the clock check, which is useful when inspecting an old capture.

### Listen locally

```bash
hookprobe listen --addr 127.0.0.1:8080 --provider auto --secret "$HOOK_SECRET" --save ./captures
```

Point the provider's "test webhook" (or `curl`) at `http://127.0.0.1:8080/webhook`. Valid deliveries return `200`; invalid ones return `401` unless you pass `--accept-invalid` (then `202`). Add `--forward http://127.0.0.1:3000/hooks` to proxy the request to your app after it is recorded.

Provider `auto` looks at `Stripe-Signature`, `X-Slack-Signature`, and `X-Hub-Signature-256` / `X-Hub-Signature`.

### Replay a capture

```bash
hookprobe replay --file captures/20261113T200000.000000-abcd1234.json --target http://127.0.0.1:3000/webhook
```

To give timestamped providers a fresh signature:

```bash
hookprobe replay --file captures/....json --target http://127.0.0.1:3000/webhook --resign --secret "$HOOK_SECRET"
```

## Tests

```bash
gofmt -w .
go vet ./...
go test -v ./...
go build -o hookprobe ./cmd/hookprobe
```

## Project layout

```text
cmd/hookprobe/          # main entrypoint
internal/signature/     # GitHub, Stripe, Slack, and generic HMAC
internal/capture/       # JSON capture format, save/load
internal/server/        # listen + forward + replay
internal/cli/           # command-line interface
```

## License

[MIT](LICENSE) © 2026 Murat Yılmaz
