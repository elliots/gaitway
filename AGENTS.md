<!-- GSD:project-start source:PROJECT.md -->

## Project

**Gaitway**

Gaitway is a self-hosted enterprise AI gateway for Claude Code, initially supporting the Anthropic Messages API only. It transparently proxies developers' existing Claude authentication while giving an internal platform team complete traffic visibility, usage controls, request scanning, centrally executed tools, and an operational dashboard without breaking normal Claude Code behavior.

The first release is a production-quality pilot for a small cohort inside one enterprise. Its core provides protocol fidelity, session and identity attribution, canonical audit events, operational persistence, telemetry, and plugin lifecycle support; compile-time plugins provide policy enforcement, usage guards, scanners, and gateway tools.

**Core Value:** Claude Code must continue working transparently while the platform team can observe, control, and safely extend every model interaction.

### Constraints

- **Language**: Implement the gateway in Go — chosen by the user for the core service and plugin contracts.
- **Protocol**: Support Claude Code through the Anthropic Messages API first — protocol fidelity and transparent pass-through take precedence over provider abstraction.
- **Compatibility**: Preserve unknown request fields and required Anthropic headers by default — Claude Code evolves and silently dropping fields can break features.
- **Persistence**: Use Postgres for operational metadata and a pluggable filesystem/S3-compatible archive for raw content — large sensitive payloads must not be coupled to relational storage.
- **Plugins**: Compile-time registration is acceptable for v1 — stable extension contracts matter now; dynamic loading can follow later.
- **Simplicity**: Keep the codebase small, clear, and idiomatic — prefer the Go standard library, direct control flow, and a modular monolith; add abstractions only when they protect a demonstrated protocol, persistence, or plugin boundary.
- **Deployment**: Support Docker Compose as the production-pilot target — Kubernetes and high availability are deferred.
- **Network**: Run the unauthenticated dashboard and admin endpoints only on a trusted private network — v1 intentionally has no dashboard authentication.
- **Identity**: Treat `whoami` and `hostname` as trusted pilot labels but not cryptographic identity — stronger corporate attestation is future work.
- **Data**: Retain all permissible raw traffic in v1 — explicit prohibited-data exclusions are still mandatory, and formal compliance hardening is deferred.
- **Testing**: Cost-capped live Claude Code end-to-end tests are a mandatory release gate — mocks alone cannot validate client compatibility or tool-history behavior.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

## Executive Recommendation

## Recommended Stack

### Core Technologies

| Technology | Exact version | Purpose | Why recommended | Confidence |
|---|---:|---|---|---|
| Go | **1.26.6** | Gateway, plugins, admin API, dashboard server, test harness | Current patched Go 1.26 release. Its standard HTTP stack already supplies HTTP/1.1 and HTTP/2, streaming bodies, cancellation, explicit flushing, reverse-proxy primitives, structured logging, embedded assets, fuzzing, and deterministic concurrency tests. | MEDIUM |
| `net/http` + `net/http/httputil` | Go **1.26.6** stdlib | Transparent HTTP/SSE proxy | `ReverseProxy.Rewrite`, `ModifyResponse`, `FlushInterval`, `BufferPool`, `ErrorHandler`, and a cloned `http.Transport` provide the necessary controls without introducing a framework that may buffer or rewrite protocol data. | MEDIUM |
| Claude Code compatibility target | **2.1.238** | Mandatory real-client release gate | This is both the locally installed version and the current npm registry version on the research date. It contains the current custom-base-URL attribution, model-discovery, and experimental-beta behavior described below. | MEDIUM |
| PostgreSQL | **18.4** | Searchable operational metadata and state | Current supported minor with five-year major support. It supplies transactions, advisory locks, JSONB, range types, generated data, `uuidv7()`, mature indexing, and recovery tooling without another state service. | MEDIUM |
| Docker Engine | **29.7.2** | Pilot container runtime | Current patched Engine 29 release; the local 29.4.0 installation trails security and bug-fix releases. | MEDIUM |
| Docker Compose | **5.5.0** | Local and single-node pilot deployment | Current Compose release. Compose v5 remains compatible with the rolling Compose Specification and is appropriate for one-host production deployment. | MEDIUM |
| OpenTelemetry Collector Contrib | **0.159.0** | OTLP receiver, batching, retry, backend routing | Keeps backend/vendor details out of the gateway and is the production-recommended hop between an application SDK and telemetry backends. | MEDIUM |

### Runtime Go Dependencies

| Library | Exact version | Purpose | When to use | Confidence |
|---|---:|---|---|---|
| `github.com/jackc/pgx/v5` | **v5.10.0** | PostgreSQL driver and pool | Use `pgxpool` for all runtime queries. v5.10.0 includes server-input hardening, authentication controls, and TLS-safe cancellation. | MEDIUM |
| `github.com/pressly/goose/v3` | **v3.27.3** | Embedded SQL migrations | Use through a dedicated `gaitway migrate` command with `embed.FS`, sequential migrations, transactions by default, and a PostgreSQL session locker. | MEDIUM |
| `github.com/aws/aws-sdk-go-v2` | **v1.43.7** | AWS SDK core | Base for S3-compatible archive implementation. Keep it behind Gaitway's storage interface. | MEDIUM |
| `github.com/aws/aws-sdk-go-v2/config` | **v1.32.38** | Credential/region/retry configuration | Use standard AWS credential resolution for AWS and explicit static/file secrets for non-AWS S3-compatible endpoints. | MEDIUM |
| `github.com/aws/aws-sdk-go-v2/service/s3` | **v1.107.3** | S3 object operations | Use `BaseEndpoint` with the default v2 endpoint resolver; opt into path-style addressing only for backends that require it. | MEDIUM |
| `github.com/aws/aws-sdk-go-v2/feature/s3/manager` | **v1.22.44** | Bounded multipart upload/download | Use above a configurable threshold; set part size and concurrency explicitly so payload size cannot imply unbounded memory. | MEDIUM |
| `go.opentelemetry.io/otel` | **v1.45.0** | OTel API and trace/metric SDK | Manual spans and metrics in the proxy path; stable trace and metric signals. | MEDIUM |
| `go.opentelemetry.io/otel/sdk` | **v1.45.0** | Trace/metric providers and batching | Configure bounded batch exporters, resource attributes, sampling, and graceful shutdown. | MEDIUM |
| `go.opentelemetry.io/otel/log` | **v0.21.0** | OTel log API | Required to emit OTel logs, but isolate behind a local adapter because Go log support remains beta. | MEDIUM |
| `go.opentelemetry.io/otel/sdk/log` | **v0.21.0** | OTel log SDK | Batch log records to the Collector; keep JSON `slog` output as an operational fallback. | MEDIUM |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` | **v1.45.0** | Trace export | OTLP/HTTP protobuf to the Collector on port 4318. | MEDIUM |
| `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp` | **v1.45.0** | Metric export | OTLP/HTTP protobuf to the Collector. | MEDIUM |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp` | **v0.21.0** | Log export | OTLP/HTTP protobuf; beta version intentionally differs from stable trace/metric versions. | MEDIUM |
| `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` | **v0.70.0** | HTTP instrumentation | Use for dashboard/admin endpoints and outbound gateway-tool clients. Prefer manual instrumentation around the fidelity-sensitive model proxy to retain full flushing/header control. | MEDIUM |
| `go.opentelemetry.io/contrib/bridges/otelslog` | **v0.20.0** | Bridge `log/slog` records to OTel | Use behind a small fan-out handler so the same sanitized event can reach JSON stdout and OTLP. | MEDIUM |
| `github.com/exaring/otelpgx` | **v0.11.1** | pgx tracing and pool metrics | Attach as `pgx` tracer and call `RecordStats`; supports Go 1.25+ and pgx v5. | MEDIUM |
| `golang.org/x/sync` | **v0.22.0** | Error-aware concurrency | Use `errgroup` for bounded concurrent gateway-tool execution and coordinated cancellation. Do not use unbounded goroutine fan-out. | MEDIUM |

### Code Generation and Dashboard Assets

| Tool/library | Exact version | Purpose | Recommendation | Confidence |
|---|---:|---|---|---|
| sqlc | **v1.31.1** | Compile SQL into typed pgx/v5 query code | Pin as a Go tool. Keep SQL visible and reviewable; generate an interface only at package boundaries that need fakes. | MEDIUM |
| `html/template` + `embed.FS` | Go **1.26.6** stdlib | Secure server-rendered dashboard and embedded assets | Use templates/fragments plus a small JSON admin API. Serve immutable hashed static assets from the binary. | MEDIUM |
| htmx | **2.0.10** | Table filters, pagination, fragment refresh | Vendor `dist/htmx.min.js`; never load dashboard code from a public CDN in the private pilot. | MEDIUM |
| Chart.js | **4.5.1** | Usage/cost/latency charts | Vendor the UMD distribution. Keep chart data in escaped JSON endpoints or non-executable JSON script blocks. | MEDIUM |
| Node.js | **24.19.0 LTS** | Browser-test toolchain only | Use current LTS for Playwright and asset provenance. Do not ship Node in the Gaitway runtime image. | MEDIUM |

### Testing and Quality Tools

| Tool/library | Exact version | Purpose | Recommendation | Confidence |
|---|---:|---|---|---|
| Go `testing`, `httptest`, fuzzing, `testing/synctest` | Go **1.26.6** | Unit, protocol fixture, fuzz, and concurrency tests | Primary test framework. Use `synctest` for timers/cancellation and native fuzzing for JSON/SSE/header parsers. | MEDIUM |
| `pgregory.net/rapid` | **v1.3.0** | Property/state-machine tests | Generate event sequences for SSE indexes, tool batches, idempotency, usage windows, and history normalization; it shrinks failures and can feed Go fuzzing. | MEDIUM |
| `github.com/testcontainers/testcontainers-go` | **v0.44.0** | Real dependency integration tests | Run PostgreSQL and S3 emulators with explicit readiness strategies and pinned images. | MEDIUM |
| `github.com/testcontainers/testcontainers-go/modules/postgres` | **v0.44.0** | PostgreSQL integration fixture | Test migrations and queries against `postgres:18.4-bookworm`, not an in-memory substitute. | MEDIUM |
| `github.com/testcontainers/testcontainers-go/modules/s3mock` | **v0.44.0** | S3 API integration fixture | Use with `adobe/s3mock:5.1.0`, path-style addressing, checksums, multipart, and fault cases. | MEDIUM |
| `github.com/testcontainers/testcontainers-go/modules/toxiproxy` | **v0.44.0** | Network fault fixture | Use with `ghcr.io/shopify/toxiproxy:2.12.0` for latency, cut connections, timeouts, and partial writes around Postgres/S3. | MEDIUM |
| Playwright Test | **1.62.1** | Dashboard browser/accessibility tests | Pin package and browser revision together. Run Chromium for every change; add Firefox/WebKit in release CI if time permits. | MEDIUM |
| `github.com/creack/pty` | **v1.1.24** | Interactive Claude Code compatibility harness | Test-only. Use only for flows unavailable in print mode, such as `/rewind` and explicit `/compact`; prefer `os/exec` everywhere else. | MEDIUM |
| govulncheck | **v1.7.0** | Reachability-aware Go vulnerability scanning | Run on source and the release binary in CI. | MEDIUM |
| golangci-lint | **v2.13.1** | Static analysis aggregation | Pin the binary/tool version and enable a curated stable set; do not let automatic lint rewrites touch protocol fixtures. | MEDIUM |

## Transparent HTTP and SSE Profile

### Use `httputil.ReverseProxy`, but own the transformation seams

### Own a small SSE codec instead of adopting a generic SSE client library

- accept LF and CRLF line endings;
- preserve comments, `event`, `id`, `retry`, unknown fields, blank separators, and upstream `ping` events;
- impose configurable line and frame bounds without `bufio.Scanner`'s small default token limit;
- raw-copy all events that do not contain a gateway-tool transformation target;
- parse only targeted `data:` JSON and rebuild only that event;
- flush after each frame;
- maintain Anthropic content-block indexes and usage/stop events exactly;
- make truncated frames, disconnects, duplicate events, and cancellation explicit test cases.

### Claude credential treatment

## PostgreSQL Profile

### Application access

- Use native `pgxpool`, not `database/sql`, for runtime code.
- Generate ordinary queries with sqlc's `sql_package: pgx/v5`.
- Configure `MaxConns`, `MinIdleConns`, acquisition timeout, connection lifetime/jitter, idle time, health-check period, and ping timeout explicitly. Defaults based on CPU count are not a production capacity plan.
- Use default extended/prepared protocol. Do not globally enable simple protocol; pgx has had simple-protocol-specific security issues, and Gaitway has no need for it.
- Attach `otelpgx.NewTracer()` and pool stats, but sanitize query attributes: raw prompt/tool content must never enter SQL text or telemetry.
- Store monetary values as integer micros or nanos plus ISO currency, not binary floating point.
- Use PostgreSQL advisory locks or row locks for idempotent tool execution and usage-window updates; keep the canonical idempotency key unique in the schema.

### Migrations

### PostgreSQL 18 container volume

## Content Archive Profile

### Filesystem implementation

- generate an opaque 128-bit random object ID; keep SHA-256 as integrity metadata rather than as the public path;
- create directories with `0700` and files with `0600`;
- stream to a temporary file in the destination directory while calculating SHA-256 and length;
- `fsync` the file, atomically rename, then `fsync` the directory before reporting success;
- reject symlink traversal and path components not generated by Gaitway;
- require encrypted host storage for the production pilot.

### S3-compatible implementation

## OpenTelemetry Profile

- Export OTLP over HTTP/protobuf to `http://otel-collector:4318`; let the Collector handle retry, batching, sampling, authentication, and backend selection.
- Traces and metrics are stable in OpenTelemetry Go 1.45.0. Logs are beta, so isolate log-provider setup and the `otelslog` bridge behind `internal/telemetry`.
- Use manual spans around the model proxy and SSE transformations. This avoids accidental wrapper behavior at the most fidelity-sensitive boundary.
- Use `otelhttp` for dashboard/admin handlers and the reference outbound HTTP gateway tool.
- Record bounded-cardinality metrics: requests, streaming outcomes, bytes, tokens, cost, policy decisions, retries, cancellation, tool duration, archive failures, and DB pool state.
- Put credential fingerprints, session IDs, agent IDs, tool IDs, and raw model IDs in traces/logs only after reviewing cardinality and sensitivity. They should not become unbounded metric labels.
- Configure batch queues and shutdown timeouts; telemetry backpressure must not block or fail model traffic.
- Never export raw prompts, responses, tool arguments/results, credentials, or full database query parameters through OTel.

## Dashboard Delivery Profile

- `/ui/` serves `html/template` pages and htmx fragments;
- `/assets/` serves embedded, content-hashed htmx, Chart.js, CSS, and minimal authored JavaScript;
- `/admin/v1/` exposes read-only JSON/fragment endpoints with cursor pagination and bounded time ranges;
- all raw-content views stream from `ContentArchive` after fetching authorization-independent pilot metadata from Postgres;
- response headers include a restrictive Content Security Policy, `X-Content-Type-Options: nosniff`, no caching for raw sensitive views, and appropriate referrer/frame policies.

## Compile-Time Plugin Contracts

- explicit interfaces for request scanners, usage policies, model-routing policies, and gateway tools;
- immutable descriptors for name, semantic contract version, execution location, access class, credentials, approval, timeout, network policy, retries, result classification, and idempotency;
- explicit constructor registration in `main` or a generated registry, not hidden `init()` ordering;
- compile-time interface assertions and a shared contract test suite;
- context cancellation and structured result/error types that do not expose storage/HTTP implementation types.

## Docker and Compose Profile

- `postgres` with a named volume at `/var/lib/postgresql` and `pg_isready` health check;
- a one-shot `migrate` service with `condition: service_healthy` on Postgres;
- `gaitway` with `condition: service_completed_successfully` on migration, a health endpoint, `restart: unless-stopped`, read-only root filesystem, and secrets mounted as files;
- an optional `otel-collector` profile;
- a filesystem archive named volume by default, or external S3-compatible configuration selected explicitly;
- S3Mock/Toxiproxy only in a test profile or test-specific Compose file.

## Claude Code 2.1.238 Gateway Contract

| Contract item | Required behavior in Gaitway | 2.1.238 note |
|---|---|---|
| Base URL | Developers set `ANTHROPIC_BASE_URL` to Gaitway. | With no gateway credential variable, the saved Claude.ai login remains active and its OAuth capability travels in `anthropic-beta`. |
| Inference endpoint | Accept `POST /v1/messages`, including requests whose URL is `/v1/messages?beta=true`; route on path while preserving raw query. | Required. |
| Token counting | Accept `POST /v1/messages/count_tokens` and apply the same request/tool-definition transform used for inference counting. | Officially optional, but required by this project for compatibility and cost controls. |
| Warm-up | Accept or harmlessly reject `HEAD /api/hello`. | Best-effort startup traffic. Return a cheap 204 to simplify diagnostics. |
| Model discovery | Optionally serve `GET /v1/models?limit=1000` directly without redirect and within three seconds. | Supported since 2.1.129; 2.1.238 accepts provider-prefixed IDs containing `claude` or `anthropic`. Defer unless the pilot needs custom models. |
| Headers | Forward `anthropic-version` and `anthropic-beta` unchanged. Treat `anthropic-*`, `x-claude-code-*`, custom headers, and body fields as open lists. | `anthropic-version` is currently `2023-06-01`; never pin beta allowlists. |
| Attribution | Preserve the `system` array and first attribution block exactly. | Stable per conversation behind custom base URLs since 2.1.181; 2.1.238 also contains the classifier exception added after 2.1.229. |
| Session/agents | Consume `x-claude-code-session-id`, `x-claude-code-agent-id`, and `x-claude-code-parent-agent-id` for attribution; do not treat agent IDs as people. | Headers must remain open-ended for future agent fields. |
| Streaming | Relay every SSE event, upstream ping, and comment immediately. Avoid a silent period approaching 300 seconds. | `ANTHROPIC_BASE_URL` connections use a byte-level watchdog; buffered/stripped pings abort long thinking. |
| Errors/retries | Preserve upstream error status and response body. | Claude Code retry/downgrade logic matches upstream error wording. |
| Fine-grained tools | Test both default behavior and `CLAUDE_CODE_ENABLE_FINE_GRAINED_TOOL_STREAMING=1`. | Fine-grained tool streaming is off by default on custom base URLs. |
| Tool search | If Gaitway forwards `tool_reference`, test with `ENABLE_TOOL_SEARCH=true`. | Claude Code disables MCP tool search by default for non-first-party base URLs. |
| Experimental betas | Pass paired beta headers/body fields unchanged; add a compatibility case with `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1`. | v2.1.238 includes the v2.1.227+ override behavior, but adaptive thinking remains separate. |

### Existing-credential compatibility is intentional

- live tests must leave `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY` unset unless testing those modes explicitly;
- Gaitway forwards the incoming auth header unchanged upstream;
- Gaitway fingerprints it in memory with HMAC and redacts it everywhere else;
- authentication refresh and 401 behavior must be tested with the real client.

## Cost-Capped Live Claude Code Test Strategy

### Machine-pinned preflight

### Headless command profile

### Budget layers

| Layer | Cap | Enforcement |
|---|---:|---|
| Simple single-turn/stream case | **$0.08 equivalent per process** | `--max-budget-usd 0.08`, low effort, 512 output-token limit, no tools, deterministic short prompt |
| Resume/fork/retry/cancel/parallel case | **$0.15 equivalent per process** | Same controls plus at most the required continuation; inject failures before upstream where possible |
| Subagent or gateway/mixed-tool case | **$0.25 equivalent per process** | One narrowly described agent/tool task, bounded tool concurrency, small tool results |
| Explicit compaction case | **$0.35 equivalent** | One prebuilt deterministic long-context fixture, low effort, short requested output |
| Entire release suite | **$2.00 equivalent default hard ceiling** | Harness reserves a case allowance before launch and sums Gaitway usage plus Claude result `total_cost_usd`; abort before the next case when exhausted |

### Required live matrix

## Installation

# Runtime dependencies

# Pinned tools

# Test dependencies

# Dashboard asset provenance and browser tests (Node 24.19.0 LTS)

## Alternatives Considered

| Recommended | Alternative | When the alternative is justified |
|---|---|---|
| Standard `net/http` + `httputil.ReverseProxy` | Envoy, NGINX/OpenResty, or a Go gateway framework | Use an edge proxy in front for TLS/load-balancing later, but not as the component that parses/mutates Anthropic JSON/SSE and reconstructs tool history. |
| Standard `ServeMux` | chi **v5.3.2** | Adopt if the admin API grows enough to need deeply nested routers and reusable middleware groups. Keep the model proxy outside generic middleware stacks. |
| pgx/sqlc | `database/sql` with handwritten scans | Acceptable for a very small schema, but sqlc reduces scan/type drift while preserving explicit SQL. |
| pgx/sqlc | GORM or another ORM | Only for a separate CRUD-heavy subsystem. It is a poor fit for audit/event, idempotency, usage-window, and JSONB queries that need explicit transactional behavior. |
| goose | golang-migrate | Use golang-migrate if the organization already standardizes on its CLI. Goose is preferred here for first-class embedding, library/provider API, transactions, and session locking. |
| AWS SDK Go v2 | MinIO Go SDK | Use MinIO's client only if the supported production object-store vendor requires MinIO-specific APIs. Gaitway needs the S3 contract, not vendor-specific management. |
| OTLP/HTTP | OTLP/gRPC | Use gRPC if the enterprise Collector standard requires it. HTTP/protobuf keeps the gateway dependency graph and network troubleshooting smaller. |
| Server-rendered htmx | React/Vite SPA | Reconsider for authenticated, write-heavy, highly interactive administration after v1. |
| Adobe S3Mock in tests | LocalStack | Use LocalStack if later phases need multiple AWS services or AWS-specific edge behavior; it is heavier than this S3-only test need. |
| Compile-time Go interfaces | RPC/WASM/dynamic plugins | Move only when runtime third-party deployment becomes an actual requirement and a security/versioning model has been designed. |

## What NOT to Use

| Avoid | Why | Use instead |
|---|---|---|
| Anthropic Go SDK in the runtime forwarding path | Generated typed request/response models cannot guarantee preservation of future unknown fields and headers. | Raw HTTP plus `json.RawMessage` at targeted transform seams. The SDK may be used only as a test oracle, never as the wire contract. |
| Fiber/fasthttp | Different HTTP semantics and ecosystem adapters add risk around HTTP/2, cancellation, standard middleware, streaming, and flush behavior. | `net/http`. |
| Gin/Echo for the model proxy | Their value is routing/binding; Gaitway needs raw pass-through and precise response control. | `httputil.ReverseProxy` plus narrow internal middleware. |
| Generic SSE parse-and-reemit library | Usually normalizes events and may drop comments, ping lines, raw line endings, unknown fields, or write timing. | Small Gaitway-owned raw frame codec with fuzz/golden tests. |
| `io.ReadAll` on unbounded request/response/tool bodies | Sensitive payloads and attachments can exhaust memory and destroy streaming/cancellation. | Bounded streaming, spill/archive, and explicit limits. |
| `http.Client.Timeout` for Anthropic inference | Total timeouts terminate valid long-running SSE streams. | Context cancellation, header/connect/TLS timeouts, and an idle-byte watchdog. |
| Error envelopes around upstream 4xx/5xx | Claude Code retry and feature fallback matches exact upstream error wording. | Preserve status/body; add Gaitway audit IDs in safe headers/logs. |
| Beta/header allowlists | Claude Code adds capabilities through new beta strings, fields, and headers. Allowlists break new versions. | Open-list forwarding with a small denylist only for hop-by-hop and Gaitway-owned secrets. |
| GORM | Hides SQL and transaction boundaries important to audit state, idempotency, and usage accounting. | pgx + sqlc. |
| Viper | Large transitive surface and implicit precedence are unnecessary for a Compose-configured single service. | Explicit `os.LookupEnv`/`_FILE` parser with startup validation. |
| Go `plugin` or runtime shared objects | Platform/version fragility and a much larger trust boundary; explicitly out of scope for v1. | Versioned compile-time interfaces and explicit registration. |
| MinIO legacy prebuilt server image for production | The community repo is archived, current CE is source-only, and legacy binaries are unmaintained. | Supported external S3/S3-compatible service; Adobe S3Mock only in tests. |
| Floating Docker tags such as `latest` | Rebuilds cease to be reproducible and can silently cross major versions. | Exact tags plus reviewed multi-arch digest locks. |
| Compose v1 / `docker-compose` / top-level `version:` | Compose v1 is legacy and the top-level schema version is obsolete. | `docker compose` and the rolling Compose Specification. |
| Automatic migrations in every server startup | Makes failures and partial rollouts harder to diagnose/recover. | One-shot `gaitway migrate` service/command. |

## Version Compatibility

| Package/tool | Compatible with | Notes |
|---|---|---|
| Go **1.26.6** | pgx 5.10.0, goose 3.27.3, AWS SDK v2, OTel 1.45.0, testcontainers 0.44.0 | All selected Go dependencies support Go 1.25 or earlier minimums; 1.26.6 is within their supported window. |
| pgx **5.10.0** | PostgreSQL **14+**, selected **18.4** | pgx states it supports PostgreSQL majors supported in the last five years; 18.4 is current. |
| goose **3.27.3** | Go **1.25+**, pgx v5 stdlib | Use pgx's stdlib adapter only inside migration tooling. |
| otelpgx **0.11.1** | Go **1.25+**, pgx **v5+**, OTel **1.45.0** | Pin all OTel stable modules together. |
| OTel trace/metrics **1.45.0** | OTel logs **0.21.0**, contrib HTTP **0.70.0**, otelslog **0.20.0** | Different major/minor numbers reflect separate stable/experimental module sets, not a mismatch. |
| PostgreSQL image **18.4-bookworm** | Volume at `/var/lib/postgresql` | Do not use the PostgreSQL 17-and-earlier mount target. |
| Docker Engine **29.7.2** | Compose **5.5.0** | The project file should use only broadly supported Specification features so local Compose 5.1.2 can still run during upgrade. |
| Playwright **1.62.1** | Node **22.x, 24.x, or 26.x**; selected **24.19.0 LTS** | Pin Playwright package and browsers together. Local Node 25 is EOL and must be replaced. |
| Claude Code **2.1.238** | Current Anthropic Messages gateway protocol | Pin the release gate to this version while also retaining forward-compatible open-list fixtures. Run a small canary suite before accepting later Claude Code versions. |

## Current Machine Gaps

| Component | Installed | Target | Action |
|---|---:|---:|---|
| Claude Code | **2.1.238** | **2.1.238** | Correct; freeze for the first compatibility baseline. |
| Go | **1.26.4** | **1.26.6** | Upgrade before implementation/release testing; 1.26.5 and 1.26.6 include security fixes. |
| Docker Engine | **29.4.0** | **29.7.2** | Upgrade before trusting image/build isolation. |
| Docker Compose | **5.1.2** | **5.5.0** | Upgrade; keep Compose file compatible during transition. |
| Node.js | **25.8.2** | **24.19.0 LTS** | Replace EOL Node 25 with supported LTS before installing Playwright. |

## Conflicts and Decisions to Surface

## Confidence Assessment

| Area | Confidence | Basis and remaining risk |
|---|---|---|
| Go/HTTP stack | MEDIUM | Current Go release and reverse-proxy/flush behavior are official; the custom targeted SSE rewrite still needs protocol fixtures and live cancellation tests. |
| PostgreSQL/tooling | MEDIUM | Versions, compatibility, and container volume change are official and cross-checked; schema/pool sizing remains workload-specific. |
| S3 archive | MEDIUM | AWS SDK behavior is official; “S3-compatible” products vary, so the chosen pilot backend needs live checksum/multipart conformance. |
| OpenTelemetry | MEDIUM | Current official versions and signal stability are clear; Go logs remain beta and backend selection is not yet specified. |
| Dashboard | MEDIUM | Versions are verified and the approach fits the requirements; final information architecture and browser support require phase-specific UI work. |
| Claude Code contract | MEDIUM | Grounded in the current official protocol reference and local 2.1.238 help/version; private tool-history behavior can only be established by live tests. |
| Live cost cap | MEDIUM | CLI flags and cost output are official/local-verified; exact spend and subscription accounting require one carefully monitored calibration run. |

## Sources

### Claude Code and Anthropic protocol

- [Gateway protocol reference](https://code.claude.com/docs/en/llm-gateway-protocol) — endpoints, open-list forwarding, headers, attribution block, streaming watchdog, errors/retries, model discovery; official, accessed 2026-08-21.
- [Other LLM gateways](https://code.claude.com/docs/en/llm-gateway) — subscription versus gateway-credential behavior; official.
- [Claude Code environment variables](https://code.claude.com/docs/en/env-vars) — `ANTHROPIC_BASE_URL`, auth headers, beta/tool-search/timeout controls; official.
- [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage) — print mode, streaming JSON, budget/session arguments; official.
- [Run Claude Code programmatically](https://code.claude.com/docs/en/headless) — result/session/usage/cost output; official.
- [Manage costs effectively](https://code.claude.com/docs/en/costs) — local estimated cost, subscription caveat, effort/context cost controls; official.
- [Claude Code npm package](https://www.npmjs.com/package/@anthropic-ai/claude-code) — registry version cross-check; official package registry.

### Go and HTTP

- [Go downloads](https://go.dev/dl/) — Go 1.26.6 current stable; official.
- [Go release history and support policy](https://go.dev/doc/devel/release) — release dates, security fixes, two-release support window; official.
- [`net/http/httputil.ReverseProxy`](https://pkg.go.dev/net/http/httputil) — `Rewrite`, raw query note, flushing and streaming behavior; official Go API docs.
- [`net/http.ResponseController`](https://pkg.go.dev/net/http#ResponseController) — flush, deadlines, full duplex; official Go API docs.
- [`encoding/json.RawMessage`](https://pkg.go.dev/encoding/json#RawMessage) — raw JSON value preservation; official Go API docs.
- [`embed`](https://pkg.go.dev/embed) and [`html/template`](https://pkg.go.dev/html/template) — embedded filesystem and contextual escaping; official Go API docs.

### PostgreSQL

- [pgx changelog](https://github.com/jackc/pgx/blob/master/CHANGELOG.md) — 5.10.0 hardening and release details; official repository.
- [pgx support policy](https://github.com/jackc/pgx) — Go/PostgreSQL support window; official repository.
- [pgxpool API](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool) — pool limits, idle/lifetime, health/ping settings; official package docs.
- [sqlc 1.31.1 releases](https://github.com/sqlc-dev/sqlc/releases/tag/v1.31.1) and [configuration](https://docs.sqlc.dev/en/latest/reference/config.html) — current version and pgx/v5 generation; official.
- [goose 3.27.3 release](https://github.com/pressly/goose/releases/tag/v3.27.3), [provider](https://pressly.github.io/goose/documentation/provider/), and [annotations](https://pressly.github.io/goose/documentation/annotations/) — embedding, locking, transactions; official.
- [PostgreSQL versioning policy](https://www.postgresql.org/support/versioning/) — 18.4 current minor and support lifecycle; official.
- [PostgreSQL official image PGDATA change](https://github.com/docker-library/docs/blob/master/postgres/README.md#pgdata) — PostgreSQL 18 volume path; official image documentation.

### S3 archive

- [AWS SDK Go v2 custom endpoints](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-endpoints.html) — `BaseEndpoint` and v2 endpoint resolver; official.
- [AWS SDK Go v2 S3 checksum behavior](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/s3-checksums.html) — upload/download checksums and multipart; official.
- [AWS SDK Go v2 S3 transfer manager](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/sdk-utilities-s3.html) — bounded multipart and failed-part cleanup; official.
- [AWS SDK Go v2 S3 changelog](https://github.com/aws/aws-sdk-go-v2/blob/main/service/s3/CHANGELOG.md) — module currency and integrity changes; official repository.
- [Adobe S3Mock 5.1.0](https://github.com/adobe/S3Mock/releases/tag/5.1.0) — maintained test emulator version; official repository.
- [MinIO source-only distribution notice](https://github.com/minio/minio/blob/master/README.md) and [archived releases](https://github.com/minio/minio/releases) — basis for excluding it as a new production server dependency; official repository.

### OpenTelemetry

- [OpenTelemetry Go status](https://opentelemetry.io/docs/languages/go/) — traces/metrics stable, logs beta; official.
- [OpenTelemetry Go exporters](https://opentelemetry.io/docs/languages/go/exporters/) — Collector production recommendation and OTLP HTTP packages; official.
- [OpenTelemetry Go 1.45.0](https://github.com/open-telemetry/opentelemetry-go/releases/tag/v1.45.0) — current stable module set; official repository.
- [OpenTelemetry Collector 0.159.0](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.159.0) — current Collector release; official repository.
- [otelpgx](https://github.com/exaring/otelpgx) — pgx v5 tracing and pool metrics with Go 1.25+ requirement; official repository.

### Dashboard, tests, and deployment

- [htmx current documentation/changelog](https://github.com/bigskysoftware/htmx/blob/master/CHANGELOG.md) — 2.0.10; official repository.
- [Chart.js 4.5.1](https://github.com/chartjs/Chart.js/releases/tag/v4.5.1) — current stable release; official repository.
- [Playwright 1.62.1](https://github.com/microsoft/playwright/releases/tag/v1.62.1), [installation](https://playwright.dev/docs/intro), and [Docker version matching](https://playwright.dev/docs/docker) — browser/toolchain compatibility; official.
- [Node.js releases](https://nodejs.org/en/about/previous-releases) — Node 24.19.0 LTS and Node 25 EOL; official.
- [Testcontainers for Go](https://golang.testcontainers.org/), [PostgreSQL module](https://golang.testcontainers.org/modules/postgres/), and [S3Mock module](https://golang.testcontainers.org/modules/s3mock/) — current 0.44.0 integration strategy; official.
- [Rapid property testing](https://github.com/flyingmutant/rapid) — generators, shrinking, state machines, fuzz integration; official repository.
- [Toxiproxy 2.12.0](https://github.com/Shopify/toxiproxy/releases/tag/v2.12.0) — network fault injection; official repository.
- [Docker Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/) — current 29.7.2 and security/bug fixes; official.
- [Docker Compose 5.5.0](https://github.com/docker/compose/releases/tag/v5.5.0), [Compose Specification](https://docs.docker.com/reference/compose-file/), [startup order](https://docs.docker.com/compose/how-tos/startup-order/), and [single-host production](https://docs.docker.com/compose/how-tos/production/) — version and deployment pattern; official.
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) — reachability-aware vulnerability scan; official Go package docs.

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
