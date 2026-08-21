# Gaitway

Gaitway is a small local gateway for Claude Code. The first runnable cut proxies
Anthropic Messages and token-count requests using Claude's existing login, while
showing a configurable activation marker on the first text response in each
Claude session.

## Run it

```bash
go run ./cmd/gaitway
```

In another terminal:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8080 claude
```

The first text response in a session should begin with:

```text
*** Gaitway Active ***
```

Gaitway uses the `x-claude-code-session-id` header. Session state is in memory,
so restarting Gaitway starts a new activation epoch. Claude may include the
marker in later conversation history; Gaitway intentionally leaves that history
unchanged.

Allowed request and client-visible response bodies are archived under `./data/content`
with opaque references, SHA-256 checksums, and `0600` permissions. Content-free audit
events are appended to `./data/audit.jsonl`. The forwarded credential is represented
only by a stable HMAC fingerprint using `./data/identity-hmac.key`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GAITWAY_LISTEN_ADDR` | `127.0.0.1:8080` | Local listen address |
| `GAITWAY_UPSTREAM_URL` | `https://api.anthropic.com` | Fixed HTTPS upstream origin |
| `GAITWAY_ACTIVATION_MESSAGE` | `*** Gaitway Active ***` | Marker text; set to an empty value to disable |
| `GAITWAY_DATA_DIR` | `./data` | Local audit and raw-content storage |
| `GAITWAY_SECRET_ACTION` | `reject` | `reject` or `allow` detected secret patterns |
| `GAITWAY_APPROVED_MODELS` | empty | Comma-separated exact Claude model allowlist; empty permits all |
| `GAITWAY_BUDGET_WINDOW` | `1h` | In-memory usage reservation window |
| `GAITWAY_BUDGET_WARNING_UNITS` | `0` | Warning threshold; `0` disables |
| `GAITWAY_BUDGET_HARD_UNITS` | `0` | Hard threshold; `0` disables |

## Test

```bash
go test ./...
go test -race ./...
```
