# Gaitway

## What This Is

Gaitway is a self-hosted enterprise AI gateway for Claude Code, initially supporting the Anthropic Messages API only. It transparently proxies developers' existing Claude authentication while giving an internal platform team complete traffic visibility, usage controls, request scanning, centrally executed tools, and an operational dashboard without breaking normal Claude Code behavior.

The first release is a production-quality pilot for a small cohort inside one enterprise. Its core provides protocol fidelity, session and identity attribution, canonical audit events, operational persistence, telemetry, and plugin lifecycle support; compile-time plugins provide policy enforcement, usage guards, scanners, and gateway tools.

## Core Value

Claude Code must continue working transparently while the platform team can observe, control, and safely extend every model interaction.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] Transparently proxy Claude Code traffic to Anthropic using the developer's existing Claude credentials.
- [ ] Preserve Anthropic Messages API compatibility, including streaming, token counting, unknown fields, required headers, stop reasons, usage, cancellation, and retries.
- [ ] Attribute traffic by credential fingerprint, Claude session and agent identifiers, and a trusted-for-v1 local `whoami`/`hostname` identity probe.
- [ ] Emit canonical, searchable audit records for requests, responses, usage, cost, policy decisions, errors, tools, approvals, and identity context.
- [ ] Store operational metadata in Postgres and raw request, response, attachment, and tool payloads through a pluggable content archive with filesystem and S3-compatible implementations.
- [ ] Retain all permissible raw traffic for the pilot, excluding only data that is explicitly prohibited from storage.
- [ ] Emit OpenTelemetry metrics, traces, and logs for gateway traffic and operational behavior.
- [ ] Provide compile-time plugin contracts for scanners, usage policies, model-routing policies, and centrally executed gateway tools.
- [ ] Ship one outbound secret-scanning plugin that records its findings and enforcement decision.
- [ ] Ship one per-user usage guard with configurable warning and hard-cap thresholds; warnings require visible user acknowledgement before continuing.
- [ ] Ship one authenticated, read-only HTTP gateway-tool plugin and support mixed local and gateway tool calls in one Claude response.
- [ ] Preserve canonical conversation history across gateway-only and mixed tool loops, including signed client-visible gateway records and idempotent execution.
- [ ] Provide a built-in operational dashboard for users, devices, sessions, raw traffic, tokens, cost, policy findings, limits, errors, and gateway-tool activity.
- [ ] Run locally and as a single-node pilot using Docker Compose with Postgres and selectable filesystem or S3-compatible content storage.
- [ ] Pass deterministic unit, property, protocol-fixture, integration, plugin-contract, browser, fault-recovery, and cost-capped live Claude Code tests before release.

### Out of Scope

- Strong user or device attestation — the pilot trusts local `whoami` and `hostname` results; signed corporate identity is deferred.
- Dashboard and admin API authentication or authorization — the pilot must run only on a trusted private network; corporate OIDC/RBAC comes later.
- Formal PCI DSS, ISO/IEC 27001, privacy, or other certification claims — the pilot records broadly, while formal minimization, retention, and certification controls are deferred.
- Multi-tenant commercial operation — v1 serves one enterprise's internal platform team.
- Providers and clients other than Claude Code using the Anthropic Messages API — broaden only after protocol fidelity is proven.
- Runtime-loaded third-party plugins — compile-time registration is sufficient for v1.
- High availability, horizontal scaling, and Kubernetes deployment — the initial production pilot is a single Docker Compose deployment.
- Automatic model fallback on usage overage — v1 warns, obtains acknowledgement, and ultimately rejects at a hard cap.
- Hiding or brokering developers' upstream Claude credentials — v1 passes their existing credentials through without storing them.

## Context

- `idea.md` is the user's source of truth. `design.md` is generated supporting material; conflicts must be resolved in favor of `idea.md` or brought back to the user.
- The gateway is intended for an internal platform team supporting developers who already use Claude Code.
- The pilot must be suitable for real traffic from a small internal cohort, not only an architectural demonstration.
- Gaitway fingerprints presented Claude credentials with a one-way HMAC and never stores the credential itself. Claude session and ephemeral agent headers group activity beneath that pseudonymous principal.
- For v1, the gateway may synthesize a one-time, read-only Bash tool request that collects `whoami` and `hostname`. These values are trusted for reporting and per-user usage controls in the pilot, but are not proof of identity and must not authorize privileged access.
- In the target managed-Mac environment, hostnames correspond to company device serial labels.
- Postgres holds identity mappings, sessions, usage totals, costs, policy decisions, tool state, searchable audit metadata, content references, checksums, classifications, retention state, and encryption metadata.
- Raw payloads are stored behind a content-archive interface. Filesystem storage supports development and simple deployments; S3-compatible storage supports the pilot's durable archive.
- The gateway sees the tool definitions sent by Claude Code, injects configured gateway tool definitions, partitions model-selected tool calls, executes gateway tools concurrently with client-side tools, and reconstructs canonical history on continuation.
- The reference gateway tool is a configurable, authenticated, read-only HTTP integration. The framework must still model execution location, access class, credentials, approvals, timeouts, network policy, result classification, retries, and idempotency.
- The dashboard has no application authentication in v1. Deployment documentation must state that it is unsafe to expose outside a trusted private network.
- Live release testing uses the locally installed Claude Code CLI (`/Users/elliot/.local/bin/claude`, version 2.1.238 at initialization), the developer's existing Claude authentication, the local Gaitway endpoint, deterministic prompts, and a strict cost budget.
- Compatibility testing covers normal continuation, streaming, token counting, retries, cancellation, session resume, rewind, conversation fork, compaction, subagents, parallel sessions, gateway-only tools, and mixed local/gateway tools.

## Constraints

- **Language**: Implement the gateway in Go — chosen by the user for the core service and plugin contracts.
- **Protocol**: Support Claude Code through the Anthropic Messages API first — protocol fidelity and transparent pass-through take precedence over provider abstraction.
- **Compatibility**: Preserve unknown request fields and required Anthropic headers by default — Claude Code evolves and silently dropping fields can break features.
- **Persistence**: Use Postgres for operational metadata and a pluggable filesystem/S3-compatible archive for raw content — large sensitive payloads must not be coupled to relational storage.
- **Plugins**: Compile-time registration is acceptable for v1 — stable extension contracts matter now; dynamic loading can follow later.
- **Deployment**: Support Docker Compose as the production-pilot target — Kubernetes and high availability are deferred.
- **Network**: Run the unauthenticated dashboard and admin endpoints only on a trusted private network — v1 intentionally has no dashboard authentication.
- **Identity**: Treat `whoami` and `hostname` as trusted pilot labels but not cryptographic identity — stronger corporate attestation is future work.
- **Data**: Retain all permissible raw traffic in v1 — explicit prohibited-data exclusions are still mandatory, and formal compliance hardening is deferred.
- **Testing**: Cost-capped live Claude Code end-to-end tests are a mandatory release gate — mocks alone cannot validate client compatibility or tool-history behavior.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Build a reliable core containing protocol handling, identity attribution, canonical audit events, persistence, OpenTelemetry, and plugin lifecycle | These invariants must remain consistent across all policies and tools | — Pending |
| Keep policy enforcement, usage guards, scanners, model routing, and gateway tools behind compile-time plugin contracts | The platform should prove extensibility without requiring runtime plugin loading in v1 | — Pending |
| Target an internal single-enterprise production pilot | Real usage is required to validate the gateway without prematurely building commercial multi-tenancy | — Pending |
| Pass existing Claude authentication through unchanged | The pilot should require minimal changes to developers' current Claude Code setup | — Pending |
| Attribute users through credential/session fingerprints plus a synthetic `whoami` and `hostname` probe | This provides useful pilot reporting without introducing enterprise identity integration yet | — Pending |
| Split Postgres operational metadata from pluggable raw-content storage | Reporting stays queryable while filesystem and S3-compatible archives can evolve independently | — Pending |
| Retain all permissible raw traffic and defer formal compliance hardening | The pilot prioritizes complete observability; prohibited storage remains excluded | — Pending |
| Use warning acknowledgement followed by a hard usage cap | Users get context before enforcement while administrators retain an absolute budget boundary | — Pending |
| Include an unauthenticated built-in dashboard | The pilot needs immediate operational visibility and will rely on private-network isolation | — Pending |
| Use Docker Compose for local and pilot deployment | A single-node deployment is sufficient for the first internal cohort | — Pending |
| Require cost-capped live Claude Code tests | Synthetic fixtures cannot prove real client streaming, history, resume, compaction, and mixed-tool compatibility | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `$gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `$gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-21 after initialization*
