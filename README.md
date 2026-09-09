# Runmantle

Runmantle is a durable, local-first Verified Execution layer for AI agents.
Wrap an existing agent, declare what success means, and Runmantle will not
report success until evidence verifies the outcome. Consequential actions and
recovery remain capability-gated, durable, and auditable when they are routed
through Runmantle's mediated boundary.

Runmantle 1.0.0 targets single-node production evaluation. It is not a
Python sandbox, distributed workflow engine, workforce manager, or fleet
control plane. Organizational memory, knowledge graphs, dashboards, RBAC,
scheduling, and workforce coordination belong to CortexOps, not Runmantle.

## Status

### Implemented

- typed asynchronous `Worker`, `TaskContract`, `TaskContext`, and `TaskResult`;
- explicit acceptance criteria, required evidence, capability allowlists, risk,
  timeout, and idempotency contracts;
- a transactional SQLite runtime with WAL, schema migrations, optimistic
  locking, explicit checkpoints, and restart-safe verification continuation;
- an in-memory runtime for tests, examples, and intentionally non-durable use;
- evidence collection and deterministic rule-based outcome verification;
- capability-mediated action execution with durable policy, authorization,
  idempotency, receipts, and postcondition evidence;
- a minimal verified action cache for exact-first recipe reuse with fresh state
  validation, repeat verification, token-savings metrics, and no approval or
  policy bypass;
- calculated evidence checksums, acquisition methods, trust levels, freshness
  requirements, and immutable persisted evidence;
- durable, approval-bound, idempotent recovery with explicit preflight,
  executor receipt, postcondition evidence, and final verification stages;
- a generic existing-agent adapter contract and native-worker bridge;
- an optional OpenAI Agents SDK adapter with real `Runner.run` integration,
  fail-closed surface inspection, and mediated local function tools;
- an optional CortexOps bridge with local JSONL, durable SQLite delivery,
  explicit OTLP, defensive redaction, and real SDK/parser compatibility tests;
- an optional synchronous CortexOps v1 control client for authenticated runtime
  registration, task-status synchronization, mediated action policy/approval,
  and exact-plan recovery review;
- in-memory, local JSONL, composite, bounded-buffer, and transport-neutral
  event sinks;
- an installable six-command durable CLI, packaged release-guard workflow, and
  dependency-free runtime package.

### Release-candidate / experimental

- public API stability until the 1.0 release candidate is promoted;
- the structural LangGraph adapter boundary, which supports only injected
  `ainvoke`, output/evidence mapping, health, and optional recovery hooks;
- adapter recovery proposal hooks;
- custom `PersistenceStore` implementations beyond the bundled SQLite store;
- receiver-side deduplication and distributed scheduling for the local
  CortexOps delivery outbox;

### Planned, not implemented

- production adapters for provider frameworks other than the supported OpenAI
  Agents SDK integration;
- distributed execution or general-purpose remote workflow scheduling;
- background policy streaming, approval push notifications, or a distributed
  control-message outbox beyond the synchronous v1 control loop.

Runmantle does not currently implement an LLM judge, provider-specific core
logic, marketplace, knowledge graph, or complex multi-agent orchestration.
It is not a Python sandbox: enforcement applies only to actions routed through
Runmantle's mediated action boundary.

## Ten-minute quickstart

Runmantle requires Python 3.11 or newer. From a clean shell, these commands
create an isolated local Git fixture and use a different CLI process at every
durable boundary:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install runmantle==1.1.1
mkdir release-guard && cd release-guard
runmantle init .
runmantle doctor
runmantle run || test $? -eq 3
runmantle verify || test $? -eq 4
runmantle resume || test $? -eq 5
runmantle resume --approve-current-plan
runmantle inspect
```

Before approval, the wrapped agent has reported completion but repository
evidence fails and the task is not successful. The approved recovery is bound
to one exact plan hash, runs once, reacquires filesystem/Git evidence, and only
then ends in `VERIFIED`. A second `resume` reports `duplicate_prevented` and
does not create another commit. Until the package is published, replace the
`pip install` line with `python -m pip install /path/to/runmantle/dist/*.whl`.

See the [Verified Release Guard guide](docs/verified-release-guard.md) and
[native worker example](examples/native_worker.py).

## Execution and verification model

A worker returns a `WorkerReport`. That report records what the worker claims;
it does not grant a verified status.

```text
pending -> running -> agent_reported_complete -> verifying -> verified
              |                                      |
              +-> failed                             +-> failed
                                                     +-> inconclusive
                                                     +-> awaiting_evidence
                                                     +-> awaiting_approval
                                                     +-> awaiting_runtime_confirmation
```

`agent_reported_complete` is deliberately separate from `verified`. The
runtime advances to `verified` only when an injected verifier evaluates the
contract's required evidence and acceptance criteria successfully. Every
successful result must include at least one explicitly declared requirement at
`RUNTIME_OBSERVED` trust or stronger, satisfied by evidence whose origin was
established at a Runmantle application boundary. This guard also applies to
custom verifier results. Output alone, agent claims, and executor receipts can
never independently grant `VERIFIED`. See
[false completion](examples/false_completion.py) for an agent-reported success
that ends in failed verification.

## Durable local runtime

`DurableRuntime` uses `SQLiteStore` by default and persists the task contract
snapshot, reported output, authoritative status, evidence, lifecycle events,
idempotency records, checkpoints, approvals, runtime confirmations, and
recovery state. State transitions and their events commit in the same SQLite
transaction and use an optimistic task version.

```python
runtime = DurableRuntime(
    database_path="./.runmantle/runtime.db",
    verifier=RuleBasedVerifier(),
)
result = await runtime.execute(worker, contract)

# A later process supplies executable application code again.
restarted = DurableRuntime(
    database_path="./.runmantle/runtime.db",
    verifier=RuleBasedVerifier(),
)
result = await restarted.resume(
    contract.task_id,
    worker=worker,
    contract=contract,
)
```

Persisted contracts are safe JSON declarations, not executable Python object
graphs. Application predicates and worker code must be supplied again after a
restart. A `RUNNING` task resumes only when the worker implements
`CheckpointedWorker.resume` and an explicit checkpoint was committed through
`TaskContext.save_checkpoint`. Runmantle never claims to restore a Python stack
frame or continue in the middle of an arbitrary function.

See [durability guarantees and limitations](docs/durability.md).

## Capability-mediated actions

`MediatedActionExecutor` persists an `ActionRequest` and evaluates the task
allowlist, registered capability, `ActionPolicy`, risk, approval, and explicit
preconditions before invoking an application handler. `SafeFunctionTool` lets
native workers and adapters route supported function tools through this
boundary.

The executor records `EXECUTING` before the handler starts, prevents repeated
execution for the same idempotency key, supports dry-run, timeout, and
cancellation, and records interrupted or restarted execution as `UNKNOWN`.
Executor-reported success remains a receipt—not a verified external outcome.
Postcondition providers acquire outcome evidence in a durable phase, and the
task verifier alone decides whether the task reaches `VERIFIED`. SQLite records
postconditions as `not_started`, `pending`, or `completed`; after a restart,
`pending` acquisition resumes without invoking the consequential handler again
and skips observations already linked to the action.

Runmantle cannot prevent arbitrary side effects performed directly by
unrestricted Python code. Keep consequential clients and credentials behind
the mediated tool boundary for these controls to apply. See
[mediated actions and the capability matrix](docs/actions.md).

The Hermes control plugin discovers its live tool registry automatically,
normalizes tool capability and risk, and routes all side-effecting or unknown
tools through governance. Manual tool enumeration is not required; optional
classification overrides remain available for application-specific semantics.

## Evidence limitations

`EvidenceItem` calculates a canonical content checksum and records attributable
content or structured payloads, source, timestamp, provenance, acquisition
method, trust level, optional expiry, artifact references, and metadata.
Persisted elevated evidence also records its framework-established acquisition
boundary and provider manifest. Worker-selected trust values and manually
constructed `INDEPENDENT` items remain agent claims for verification. Only an
exact built-in boundary or an application-registered provider can establish
elevated effective trust. `EvidenceRequirement` defaults to
`RUNTIME_OBSERVED`, can require stronger trust and maximum age, and must be
explicitly present for successful verification. Undeclared evidence is not
passed to acceptance criteria; expired, future-dated, or insufficiently trusted
evidence is unavailable to verification.

Evidence emitted by a worker or adapter does not independently prove every
external side effect. For example, an adapter response is not by itself proof
that a remote message was delivered, a transaction settled, or state remained
persisted. Contracts that depend on those effects need suitable independent
evidence or runtime confirmation supplied by the application.

No LLM judge is used by the built-in verifier.

## Recovery safety

A `RecoveryPlan`, including one suggested by an agent, is only a proposal.
`DurableRecoveryExecutor` persists the exact plan and action hashes, diagnosis,
context reference, capability, risk, approval requirement, preconditions,
postconditions, and optional compensation interface identifier. It can pause,
stop, accept an authenticated-boundary decision in another process, and resume
from SQLite without repeating the recovery handler.

Recovery uses four deliberately separate artifacts:

1. `PreActionCapabilityConfirmation` confirms before execution that the local
   runtime supports the exact action. The old `RuntimeConfirmation` name is a
   compatibility alias and `requires_runtime_confirmation` is deprecated
   terminology for this preflight gate.
2. `RecoveryExecutionReceipt` reports what the injected executor returned.
3. `RecoveryPostcondition` acquires external outcome evidence.
4. The task verifier alone determines whether the final outcome is `VERIFIED`.

An interrupted recovery becomes `UNKNOWN` and its idempotency key remains
consumed. A failed or missing postcondition leaves the original task unchanged;
Runmantle never optimistically marks the task recovered. `InMemoryRecoveryExecutor`
remains available for compatibility and intentionally non-durable tests.

`RecoveryPolicy.safe_default()` permits no recovery capabilities. Runmantle
does not provide shell, deployment, filesystem, or external API recovery
handlers. See [the recovery example](examples/recovery_flow.py) for a real
persisted pause followed by approval and resume through a second executor
instance. See [durable approvals and recovery](docs/approvals-and-recovery.md).

## Adapters and telemetry

`AgentAdapterWorker` lets an existing agent participate in the same runtime and
verification flow as a native worker. The application remains responsible for
mapping the agent's task input, output, evidence, health, and optional recovery
proposal hooks. See [the existing-agent example](examples/existing_agent_adapter.py).

Install `runmantle[openai-agents]` to wrap an OpenAI `Agent` and its `Runner`
without adding OpenAI to Runmantle core. Normal runner return is only an agent
completion claim. Consequential local `FunctionTool` calls can be wrapped with
`mediate_openai_function_tool`; hosted tools, MCP, handoffs, and agent-as-tool
paths are rejected in fail-closed mode or explicitly observe-only. See the
[OpenAI Agents adapter guide](docs/openai-agents.md).

## CortexOps integration

Runmantle includes an optional, disabled-by-default, observation-only CortexOps
integration. Local JSONL remains the default, now backed by a transactional
SQLite outbox with stable IDs, restart-safe at-least-once delivery, bounded
retry, batching, flush/close, and dead-letter visibility. Setting an OTLP
endpoint explicitly uses the optional official CortexOps SDK. Content-bearing
fields are redacted unless separately opted in. Core has no CortexOps dependency
and the observation bridge grants no recovery, approval, enforcement, or
control authority.

Separately, `runmantle.integrations.cortexops_control` provides an explicit,
synchronous v1 control client. A `control` + `live` handshake can route mediated
actions through CortexOps policy and exact-hash one-time approvals, submit exact
recovery plans for review, and return runtime receipts plus final verification.
It is disabled unless the application constructs it, supplies authentication,
and uses the controlled action/recovery wrappers. Offline or stale authority
fails closed. `observe` and `demo` registrations cannot authorize execution.

See [CortexOps integration setup and limitations](docs/cortexops.md) and the
[local export example](examples/cortexops_export.py).

Lifecycle events include task start/progress/failure, tool or action requests,
evidence collection, agent-reported completion, verification results, and
recovery decisions. The original root-level `CortexOpsEventSink` remains a
generic application-owned transport boundary for backward compatibility. The
optional `runmantle.integrations.cortexops` module targets the public
`cortexops-sdk` exporter contract discovered in the CortexOps repository.

## Examples

- [Deterministic CLI worker](examples/deterministic_worker.py)
- [Native worker](examples/native_worker.py)
- [Existing-agent adapter](examples/existing_agent_adapter.py)
- [OpenAI Agents SDK quickstart](docs/openai-agents.md#quickstart)
- [False completion and failed verification](examples/false_completion.py)
- [Persisted approval pause and durable recovery resume](examples/recovery_flow.py)
- [CortexOps-compatible local event export](examples/cortexops_export.py)

Run an example from the repository root with `PYTHONPATH=src`, for example:

```bash
PYTHONPATH=src python examples/false_completion.py
```

## Development and quality checks

```bash
python -m pip install -e '.[dev]'
python -m pytest
ruff check src tests examples
ruff format --check src tests examples
mypy
python -m build
```

The CI workflow also installs the built wheel into a clean virtual environment
and runs the packaged CLI outside the source tree.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor workflow and
[docs/api.md](docs/api.md) for the public API reference.

For release-candidate operations, read [security and operational
limits](docs/security-and-operations.md) and the [developer-preview migration
guide](docs/migration-v1.md).

## Independence and license

Runmantle is independently deployable, has no runtime dependencies, and works
without CortexOps. Optional observation and control integrations remain behind
explicit, application-supplied interfaces and authentication.

Runmantle is licensed under the [MIT License](LICENSE).
