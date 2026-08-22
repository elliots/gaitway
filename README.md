# Gaitway

Gaitway is a small enterprise gateway for Claude Code. It preserves the
Anthropic Messages API and developers' existing Claude login while adding:

- complete request/response archiving with credential-safe identity attribution;
- secret, approved-model, and reconciled per-user usage controls;
- OpenTelemetry logs, metrics, and traces;
- an optional, centrally executed read-only HTTPS tool;
- PostgreSQL audit metadata and filesystem or S3-compatible raw storage;
- a read-only operational dashboard.

The code is one Go process with compile-time plugin seams. Normal model traffic
stays on the transparent reverse-proxy path; tool coordination is opt-in.

## Run locally

```bash
go run ./cmd/gaitway
```

In another terminal:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8080 claude
```

```text
*** Gaitway Active ***
```

The dashboard is at <http://127.0.0.1:8081>. It has no application
authentication and must stay on a trusted private interface.

Raw request, response, and tool payloads default to `./data/content`. Audit
metadata defaults to `./data/audit.jsonl`. The forwarded Claude credential is
never persisted; only a keyed HMAC fingerprint is retained.

For Claude Code OAuth credentials, Gaitway calls Anthropic's profile endpoint
once per unseen token fingerprint and records the returned account and
organization IDs, email, display name, and full name. It never stores the bearer
token. Persisted audit mappings are restored after a restart.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GAITWAY_LISTEN_ADDR` | `127.0.0.1:8080` | Claude API listen address |
| `GAITWAY_ADMIN_ADDR` | `127.0.0.1:8081` | Read-only, unauthenticated dashboard |
| `GAITWAY_UPSTREAM_URL` | `https://api.anthropic.com` | Fixed HTTPS Anthropic origin |
| `GAITWAY_ACTIVATION_MESSAGE` | `*** Gaitway Active ***` | Empty disables the marker |
| `GAITWAY_OAUTH_PROFILE` | `true` | Resolve stable Anthropic account and organization IDs once per token fingerprint |
| `GAITWAY_DATA_DIR` | `./data` | Local keys, audit fallback, and filesystem archive |
| `DATABASE_URL` | empty | PostgreSQL URL; empty uses JSONL audit metadata |
| `GAITWAY_ARCHIVE_BACKEND` | `filesystem` | `filesystem` or `s3` |
| `GAITWAY_S3_ENDPOINT` | empty | Absolute S3-compatible endpoint |
| `GAITWAY_S3_REGION` | empty | S3 region when required |
| `GAITWAY_S3_BUCKET` | empty | Raw-content bucket |
| `GAITWAY_S3_PREFIX` | empty | Optional object-key prefix |
| `GAITWAY_S3_ACCESS_KEY` | empty | S3 access key |
| `GAITWAY_S3_SECRET_KEY` | empty | S3 secret key |
| `GAITWAY_S3_SESSION_TOKEN` | empty | Optional temporary session token |
| `GAITWAY_S3_ALLOW_HTTP` | `false` | Permit plain HTTP for local MinIO only |
| `GAITWAY_S3_CREATE_BUCKET` | `false` | Create a missing bucket at startup |
| `GAITWAY_SECRET_ACTION` | `reject` | `reject` or `allow` detected secret patterns |
| `GAITWAY_APPROVED_MODELS` | empty | Comma-separated exact Claude model allowlist |
| `GAITWAY_BLOCKED_MODEL_FAMILIES` | `haiku` | Case-insensitive model-name fragments to reject |
| `GAITWAY_BUDGET_WINDOW` | `4h` | Per-principal usage window |
| `GAITWAY_BUDGET_WARNING_UNITS` | `0` | Visible acknowledgement threshold; `0` disables |
| `GAITWAY_BUDGET_HARD_UNITS` | `0` | Reject the request after recorded usage reaches this token cap; `0` disables |
| `GAITWAY_BUDGET_LIMIT_MESSAGE` | `Gaitway usage limit reached` | Prefix for the limit error; usage, window, and reset time are appended |
| `GAITWAY_OTEL_ENDPOINT` | empty | OTLP/HTTP base URL; empty disables export |
| `GAITWAY_TOOLS_ENABLED` | `false` | Enable central tool injection and coordination |
| `GAITWAY_HTTP_TOOL_HOSTS` | empty | Exact comma-separated HTTPS host allowlist |
| `GAITWAY_HTTP_TOOL_PATHS` | empty | Comma-separated path-prefix allowlist |
| `GAITWAY_HTTP_TOOL_BEARER_TOKEN` | empty | Optional downstream bearer credential |
| `GAITWAY_HTTP_TOOL_ALLOW_PRIVATE` | `false` | Permit private IPs for deliberate local testing |
| `GAITWAY_HTTP_TOOL_TIMEOUT` | `10s` | Central HTTP tool deadline |
| `GAITWAY_HTTP_TOOL_MAX_RESULT_BYTES` | `1048576` | Central HTTP result limit |

Gateway tool names use the reserved `gaitway__` prefix. The bundled
`gaitway__http_get` tool accepts only configured HTTPS hosts and paths, blocks
private/link-local destinations by default, does not follow an unapproved
redirect, bounds results, coalesces duplicate executions, and keeps the brief
mixed local/gateway-tool handoff in bounded process memory. Internal tool state
is never printed into Claude's transcript.

The default 5,000-token budget is a deliberately simple five-cent equivalent
at Claude Sonnet 5's current $10-per-million output-token price. Input, output,
cache-read, and cache-write tokens all count equally, so it is a conservative
test control rather than invoice accounting. The request that crosses the cap
finishes; the following request is rejected.

## Docker Compose

Filesystem archive:

```bash
docker compose up --build
```

Local S3-compatible archive through MinIO:

```bash
GAITWAY_ARCHIVE_BACKEND=s3 docker compose --profile s3 up --build
```

Compose binds all published ports to host loopback. See
[`docs/operations.md`](docs/operations.md) before moving the pilot to a private
network.

## Verify

```bash
go test ./...
go test -race ./...
go vet ./...
docker compose config --quiet
docker build --check .
```

Optional Docker-backed tests:

```bash
GAITWAY_TEST_DATABASE_URL='postgres://gaitway:gaitway-local-only@127.0.0.1:5432/gaitway?sslmode=disable' go test -run TestPostgresIntegration ./internal/postgres
GAITWAY_TEST_S3_ENDPOINT=http://127.0.0.1:9000 go test -run TestS3Integration ./internal/archive
```

The real-client smoke suite is [`scripts/live-test.sh`](scripts/live-test.sh).
It is opt-in and enforces a Claude CLI budget ceiling.
