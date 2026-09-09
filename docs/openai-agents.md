# OpenAI Agents SDK adapter

Runmantle 1.1.1 supports OpenAI Agents SDK 0.22 as an optional integration. The
core package stays provider-neutral and does not import or install OpenAI.

```bash
python -m pip install 'runmantle[openai-agents]'
```

The version range is deliberately narrow because this adapter depends on the
SDK's concrete `Agent`, `Runner.run`, `RunHooks`, `FunctionTool`, result-item,
and exception contracts. Upgrade support must be validated against installed
source and the official SDK documentation before widening it.

## Quickstart

The installed package includes an executable quickstart using a real SDK
`Agent`, `Runner.run`, and mediated `FunctionTool`, backed by an SDK `Model`
implementation that returns fixed local responses:

```bash
python -m pip install 'runmantle[openai-agents]'
env -u OPENAI_API_KEY python -m runmantle.openai_quickstart
```

It makes no network call and requires no API key. Its JSON output demonstrates
that normal agent return stops at `awaiting_evidence`, a mediated tool with a
missing task capability fails without invoking the function, separately
acquired evidence from an explicitly registered independent provider is
recorded through a mediated postcondition, and only subsequent verification
reaches `verified`. The source is `runmantle.openai_quickstart` in the installed
wheel.

## Mapping and guarantees

`OpenAIAgentsAdapter` maps a `TaskContract` to SDK input with a configurable
`input_mapper`. The default passes string input unchanged and safely JSON
encodes other inputs with task ID, objective, and input. `Runner.run` receives:

- the existing `Agent`;
- application context from `context_factory`;
- Runmantle's correlation ID as the OpenAI trace `group_id`;
- task, correlation/session, worker, capability, and idempotency metadata in
  OpenAI trace metadata;
- an optional SDK session from `session_factory`;
- Runmantle lifecycle hooks, maximum turns, timeout, and cancellation.

By default the session ID equals the correlation ID. Set a non-empty
`TaskContract.metadata["session_id"]` to propagate a distinct application
session ID into adapter context, trace metadata, and mediated-action metadata.
`session_factory` can turn that metadata into an SDK `Session` instance.

The SDK's `final_output` passes through `output_mapper` and becomes
`WorkerReport.completed`. That advances only to `AGENT_REPORTED_COMPLETE`.
An optional `evidence_mapper` may add attributable agent/adapter evidence. It
always enters through the worker report boundary as `AGENT_CLAIM`, even if the
mapper constructs an item marked `INDEPENDENT`. Elevated trust requires a
registered provider invoked by a mediated postcondition. The task's Runmantle
verifier remains authoritative and only `VERIFIED` is success.

SDK `AgentsException` failures become structured worker failures. Cooperative
Runmantle cancellation cancels the SDK run. A task timeout also cancels the SDK
run and never reports success. SDK approval interruptions are rejected as a
worker failure: the SDK's in-memory/serialized `RunState` continuation is not
claimed as a Runmantle durable checkpoint.

## Mediated function tools

`mediate_openai_function_tool` accepts an existing SDK `FunctionTool`, retains
its name, description, parameter schema, strictness, and enabled metadata, and
replaces invocation with a Runmantle `ActionExecutor` boundary. The
approval-bound handler identity hashes the tool name, JSON parameter schema,
strictness, and stable callable code identity. Each call uses
the SDK call ID plus task/tool identity for a stable action ID and idempotency
key. Runmantle persists and authorizes the action before invoking the original
tool. Capability, risk, preconditions, approval, dry-run, timeout,
cancellation, receipt, and postcondition semantics are those documented in
[mediated actions](actions.md).

The wrapper disables the SDK's normal "tool error as model-visible output"
fallback. A denied, interrupted, unknown, or failed mediated action aborts the
agent run instead of letting a model reinterpret a safety failure. On restart,
an abandoned `EXECUTING` action becomes `UNKNOWN`; it is not executed again or
reported as successful.

## Enforcement matrix

| SDK path | Fail-closed mode | Observe-only mode | Actual Runmantle authority |
|---|---|---|---|
| Wrapped local `FunctionTool` | Allowed | Allowed | Full mediated action boundary |
| Unwrapped local `FunctionTool` | Rejected before runner | Allowed with warning events | None |
| Hosted tools (web, file search, code interpreter, image, computer, shell) | Rejected | Allowed with observations available from SDK hooks/items | None; execution is hosted |
| Local MCP server tools | Rejected when `mcp_servers` is configured | Allowed with warning | None; SDK discovers/invokes them |
| Hosted MCP tool | Rejected | Allowed with warning | None; round trip is provider-hosted |
| Handoff | Rejected conservatively | Allowed with warning/events | No enforcement of destination agent paths |
| Agent-as-tool | Rejected | Allowed with warning/events | No enforcement inside nested runner |
| Dynamically introduced/uninspectable path | Not supported; application must reject it | Observe-only | None |

Fail-closed inspection is intentionally conservative and covers the supplied
starting agent's current static configuration. It does not claim to prove that
arbitrary unrestricted Python cannot create side effects. Keep credentials and
consequential clients behind mediated functions if this boundary is meant to
enforce policy.

## Tracing versus lifecycle events

OpenAI tracing records SDK spans for runs, model calls, function tools, and
handoffs. Runmantle adds its identifiers to trace metadata for correlation,
but an OpenAI trace is observation—not policy authorization, durable action
state, external postcondition evidence, or verification.

Runmantle lifecycle events record adapter observations, while durable action
events and SQLite records are the authority for mediated decisions. Even a
normal trace and tool-output item only establish what the SDK reported. They
do not independently prove delivery, persistence, settlement, or other
external side effects.

## SDK references used for this adapter

- [Running agents](https://openai.github.io/openai-agents-python/running_agents/)
- [Tools](https://openai.github.io/openai-agents-python/tools/)
- [Results](https://openai.github.io/openai-agents-python/results/)
- [Lifecycle hooks](https://openai.github.io/openai-agents-python/ref/lifecycle/)
- [MCP](https://openai.github.io/openai-agents-python/mcp/)
- [Handoffs](https://openai.github.io/openai-agents-python/handoffs/)
- [Tracing](https://openai.github.io/openai-agents-python/tracing/)
- [Exceptions](https://openai.github.io/openai-agents-python/ref/exceptions/)

## Remaining limitations

There is no streaming adapter API yet; the integration uses `Runner.run`, not
`run_streamed`. Runmantle does not durably serialize an SDK `RunState`, replay
an arbitrary SDK conversation, inspect tools added after static validation,
mediate hosted or MCP tools, recursively validate handoff graphs, or reconcile
an `UNKNOWN` external action automatically. `health()` reports `UNKNOWN`
because constructing the adapter does not probe credentials, network access,
or model availability. An inline mediated action that pauses for Runmantle
approval persists its approval request, but this adapter cannot yet durably
resume the enclosing SDK run at that tool call; use a framework boundary
outside the runner for approval-bound workflows.
