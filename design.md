# Claude Enterprise Gateway Design

## Goals

- Proxy Claude API traffic from Claude Code.
- Authenticate and attribute every request to a developer.
- Hide Anthropic and downstream service credentials.
- Track usage, cost, tools, policy decisions and errors.
- Inject centrally executed tools into Claude requests.
- Support local and gateway tools in the same Claude response.
- Preserve enough information in Claude Code’s history to reconstruct the canonical conversation.

## Architecture

```text
Claude Code
    │
    │ Claude Messages API
    ▼
Enterprise Gateway
    ├── Authentication and identity
    ├── Request policy and DLP
    ├── Claude protocol adapter
    ├── Tool injection
    ├── Tool execution coordinator
    ├── Credential broker
    ├── Audit and usage events
    └── Reporting API
          │
          ├── Anthropic
          ├── Enterprise tool workers
          ├── GitHub / Jira / CI / internal APIs
          └── Vault / cloud secret manager
```

## Request processing

1. Authenticate the developer using a short-lived corporate identity token.
2. Record the developer, team, Claude Code session and agent identifiers.
3. Scan the request for secrets, PII and policy violations.
4. Add permitted gateway tool definitions to the request.
5. Forward the transformed request to Anthropic.
6. Stream the response through the protocol adapter.

Unknown request fields and headers should be preserved by default.

## Tool execution

Claude may return local and gateway tools in the same assistant response:

```text
assistant:
    local tool A
    gateway tool B
    local tool C
```

The gateway partitions the calls:

```text
Local tools   → Claude Code
Gateway tools → Central tool workers
```

Both groups execute concurrently. Tools in the same Claude response cannot depend on one another’s results because Claude selected them before any result existed.

## Client-visible representation

Gateway tool calls should remain visible in Claude Code’s history.

Preferred representation:

```text
mcp_tool_use
mcp_tool_result
```

Fallback representation:

```text
Signed assistant text envelope containing:
- tool ID
- tool name
- arguments
- result
- error status
- gateway signature
```

The signature prevents client-created text from being interpreted as an authoritative gateway result.

## Mixed tool sequence

### First response to Claude Code

```text
assistant:
    gateway tool request representation
    local tool request
```

At the same time, the gateway starts executing the gateway tool.

### Claude Code continuation

Claude Code executes the local tool and sends:

```text
user:
    local tool result
```

### Canonical request sent to Claude

The gateway reconstructs:

```text
assistant:
    gateway tool_use
    local tool_use

user:
    gateway tool_result
    local tool_result
```

It then calls Claude again.

### Second response to Claude Code

```text
assistant:
    gateway tool result representation
    Claude continuation
```

Claude Code’s stored history now contains the gateway request, gateway result, local request and local result.

## History normalisation

Every later Claude Code request is normalised before being sent upstream.

```text
Claude Code-visible history
    gateway request representation
    gateway result representation
    local tool_use
    local tool_result

        ↓ normalisation

Canonical Claude history
    assistant:
        gateway tool_use
        local tool_use
    user:
        gateway tool_result
        local tool_result
```

This avoids maintaining a separate hidden conversation transcript.

The gateway still stores authoritative audit records and verifies that visible gateway records match previously executed tools.

## Gateway-only tools

When a response contains only gateway tools, the gateway can complete the internal tool loop before returning control to Claude Code:

```text
Claude requests gateway tool
    → gateway executes tool
    → gateway returns result to Claude
    → Claude continues
    → gateway sends visible tool request, result and continuation to Claude Code
```

## Gateway state

Store pending tool batches keyed by:

```text
developer ID
session ID
agent ID
upstream message ID
tool_use ID
```

Each batch records:

```text
- canonical assistant response
- client-visible representation
- local tool IDs
- gateway tool IDs
- gateway execution status
- gateway results
- approval state
- timestamps
- retry and idempotency keys
```

Tool execution must be idempotent. Retries must not create duplicate tickets, deployments or other side effects.

## Streaming

The protocol adapter must:

- Parse Anthropic SSE events.
- Forward text, thinking and local tool blocks.
- Rewrite gateway tool blocks into the client-visible representation.
- Maintain valid content-block indexes.
- Send keepalive events during gateway execution.
- Propagate cancellation to Anthropic and tool workers.
- Return valid usage and stop-reason information.

The same transformations must be applied to token-counting requests.

## Tool security

Each gateway tool defines:

```text
execution location
read/write classification
required roles
credential mode
approval policy
timeout
network policy
result classification
```

Credential modes:

```text
Delegated user OAuth
    Actions use the developer’s downstream identity.

Shared workload identity
    Used for controlled internal read-only services.

Approval-bound privileged identity
    Used for elevated operations after explicit approval.
```

Tool workers must independently authorise every call. Client-side approval is not sufficient authorisation.

## Compliance

Inspect:

```text
- prompts
- attached content
- tool arguments
- tool results
- model responses
- persisted logs
```

Possible decisions:

```text
allow
reject
redact
require approval
route to an approved model
run through a restricted tool
```

Gateway results are sent to the developer’s machine. The tool must not return data the authenticated developer is not permitted to access.

## Tracking and reporting

Record:

```text
- developer and team
- session and agent
- model
- input, output and cache tokens
- estimated and actual cost
- latency and errors
- policy and DLP decisions
- injected tools
- requested and executed tools
- approvals and denials
- downstream execution identity
- tool duration and result status
- task classification
```

Raw prompts and tool results should have separate retention and access policies from aggregate reporting data.

## Compatibility validation

Test the client-visible gateway representation against supported Claude Code versions for:

```text
- normal continuation
- streaming
- retries
- cancellation
- session resume
- rewind
- conversation fork
- compaction
- subagents
- parallel sessions
```

Use structured MCP-style blocks when Claude Code preserves them reliably. Otherwise use signed text envelopes.
