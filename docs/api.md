# Public API reference

This document describes the public interfaces exported by `runmantle` for the
1.0 release candidate. APIs may still evolve before final 1.0.
Provider-specific behavior and CortexOps platform APIs are not part of the core
contract.

## Execution contracts

### `Worker[InputT, OutcomeT]`

Protocol implemented by native workers. A worker exposes `id`, `name`, `role`,
`version`, `capabilities`, and:

```python
async def execute(
    task: TaskContract[InputT, OutcomeT],
    context: TaskContext,
) -> WorkerReport[OutcomeT]: ...
```

`FunctionWorker` adapts an async typed callable to this protocol.

### `TaskContract[InputT, OutcomeT]`

Immutable declaration containing:

- `task_id`, `objective`, and typed `input`;
- `acceptance_criteria` and `required_evidence`;
- `allowed_capabilities`, `risk_level`, and `timeout`;
- `idempotency_key` and application `metadata`.

A contract must contain at least one acceptance criterion. Construction still
accepts an empty `required_evidence` tuple for source compatibility, but such a
contract cannot reach `verified` through the runtime verification gate.

### `TaskContext`

Runtime-owned execution context containing a correlation ID, task metadata,
cancellation token, task-bound event emitter, dependency resolver, evidence
collector, and the intersection of worker-declared and task-allowed
capabilities. `require_capability(name)` rejects undeclared use locally.
`save_checkpoint(...)` is available only when the runtime supplies a durable
`CheckpointWriter` and the `checkpoint` capability is allowed.

### `WorkerReport[OutcomeT]`

An agent's reported output, status, evidence, and errors. Use
`WorkerReport.completed(output)` or `WorkerReport.failed(...)`. Completion is a
report, not a verification decision.

### `TaskResult[OutcomeT]`

The runtime result containing task/correlation IDs, authoritative lifecycle
status, worker-reported status, output, evidence, structured errors,
timestamps, and an optional final `VerificationResult`. `succeeded` is true
only when the authoritative status is `verified`.

### Cancellation and dependencies

- `CancellationToken`: `cancel()`, `wait()`, `is_cancelled`, and
  `raise_if_cancelled()`.
- `TaskCancelledError`: cooperative cancellation signal.
- `DependencyKey[T]` and `DependencyResolver`: typed dependency injection port.
- `InMemoryDependencies`: local type-checking dependency container.

## Lifecycle and runtime

### `TaskStatus`

`pending`, `running`, `agent_reported_complete`, `verifying`, `verified`,
`failed`, `inconclusive`, `awaiting_evidence`, `awaiting_approval`, and
`awaiting_runtime_confirmation`.

### `InMemoryRuntime`

```python
await runtime.execute(
    worker,
    contract,
    cancellation=None,
    correlation_id=None,
)
```

Executes one worker with timeout/cancellation guards, collects evidence, emits
events, and invokes the optional verifier. It performs no remote side effects.
It is explicitly non-durable and cannot resume after process termination.

### `DurableRuntime`

`DurableRuntime` defaults to `SQLiteStore("./runmantle.db")` and exposes:

- `start(worker, contract)`: atomically create a `pending` task without running
  application code;
- `execute(worker, contract)`: create and run a new durable task;
- `load(task_id)` / `load_task(task_id)`: load a `StoredTask` snapshot;
- `resume(task_id, worker=..., contract=...)`: continue from the persisted
  lifecycle boundary;
- `add_evidence`, legacy `request_approval` / `decide_approval`, and
  `add_runtime_confirmation`;
- `create_approval_request`, `record_approval_decision`, `revoke_approval`, and
  `load_approval` for exact typed approvals;
- `verify_after_recovery` for the guarded postcondition-to-verification
  boundary used by `DurableRecoveryExecutor`;
- `event_history(task_id)`: read all internal events in sequence order.

`resume` requires the executable `TaskContract` again because callable Python
criteria are not deserialized from storage. `worker` is required for pending
execution and checkpoint resumption, but not for verification-only
continuation.

### Persistence

`PersistenceStore` is the full persistence protocol. `SQLiteStore` implements
it with transactions, foreign keys, WAL and `synchronous=NORMAL` for file-backed
databases, a busy timeout, schema migrations, unique event/evidence IDs, and
optimistic task versions.

Public durable models include `StoredTask`, `ContractSnapshot`,
`CheckpointRecord`, `ApprovalRequest`, `ApprovalDecision`,
`ApprovalRevocation`, `StoredApproval`, `RecoveryStateRecord`, and
`IdempotencyRecord`. `ApprovalRecord` is retained for the legacy API.
Persistence failures use `PersistenceError` subclasses,
including `ConcurrentUpdateError`, `InvalidTransitionError`,
`CorruptStoreError`, and `SchemaVersionError`.

The default `SafeJsonCodec` never uses pickle. Dataclasses become JSON objects;
bytes, aware datetimes, timedeltas, and paths use validated tagged JSON values.
Unsupported values are rejected rather than executed or stringified.

### Mediated actions

`ActionRequest` is an immutable proposal containing task/action identity,
required capability, safely serializable input, calculated input/action hashes,
idempotency key, risk, timeout, preconditions, postconditions, and request
provenance. Construction grants no execution authority.

`ActionExecutor` is the execution protocol. `MediatedActionExecutor` is its
durable implementation over `PersistenceStore`. It records separate
`ActionPolicyDecision`, `PreActionAuthorization`, `StoredAction`, and
`ActionReceipt` records. `ActionExecutionStatus` includes `requested`,
`policy_decided`, `awaiting_approval`, `authorized`, `blocked`, `executing`,
`executor_succeeded`, `failed`, `unknown`, `cancelled`, and `dry_run`.
`StoredAction.postcondition_status` is `not_started`, `pending`, or `completed`.
Executor success enters `pending`; exact retries collect missing postconditions
without reinvoking the handler and finish at `completed`.

`ActionPolicy.safe_default()` denies all capabilities. Authorization evaluates
the task capability allowlist, caller-granted capabilities, runtime
`CapabilityRegistry`, task state, risk limits, exact persisted approval, and
`Precondition` results. A handler is invoked only after `EXECUTING` commits.

`SafeFunctionTool` wraps a synchronous or asynchronous function for native
workers and adapter-backed workers. Its `invoke(...)` method uses the
`TaskContext` capability intersection and cancellation token. This mediates
only calls made through the wrapper; Runmantle does not sandbox arbitrary
Python or intercept direct side effects.

### Optional OpenAI Agents SDK adapter

Install `runmantle[openai-agents]`, then import from
`runmantle.integrations.openai_agents`. `OpenAIAgentsAdapter` implements the
generic `AgentAdapter` boundary using the SDK's actual `Runner.run` API.
`OpenAIAgentsRunMetadata` carries task, correlation/session, worker,
capability, idempotency, and timeout context. `mediate_openai_function_tool`
wraps a local SDK `FunctionTool` with `ActionExecutor` while retaining its
schema and tool metadata.

`OpenAIAgentsEnforcementMode.FAIL_CLOSED` rejects a starting agent when static
inspection finds any unmediated function tool, hosted tool, MCP server,
handoff, or agent-as-tool path. `OBSERVE_ONLY` permits those paths and emits
events that explicitly disclaim enforcement. Runner return, tool output, and
OpenAI trace completion never grant verification. The complete support matrix
and limitations are in [the OpenAI Agents adapter guide](openai-agents.md).

`ExecutorResult` is the handler return contract. `ActionReceipt` is the
executor's durable claim, not external proof. `Postcondition` invokes an
`ActionEvidenceProvider` after executor-reported success. See
[the exact capability matrix](actions.md).

### Checkpoint boundary

`CheckpointedWorker` adds:

```python
async def resume(
    task: TaskContract[InputT, OutcomeT],
    context: TaskContext,
    checkpoint: CheckpointRecord,
) -> WorkerReport[OutcomeT]: ...
```

A checkpoint is application state captured at a deliberate boundary. It does
not contain a coroutine, stack frame, local variables not placed in the
payload, open connection, or uncommitted external effect.

## Evidence

### `EvidenceItem`

Immutable evidence with `evidence_id`, `type`, textual `content` or structured
`payload`, `source`, aware `collected_at`, `provenance`, optional
`artifact_reference`, calculated `checksum`, `metadata`, `acquisition_method`,
`trust_level`, optional `expires_at`, framework-established `trust_origin`, and
`origin_hash`. Nested mappings and sequences are frozen at construction. A
supplied mismatched checksum or persisted origin mismatch raises
`EvidenceIntegrityError`. `effective_trust_level` is capped at `AGENT_CLAIM`
unless Runmantle established the origin through a mediated built-in or
application-registered provider boundary.

### `EvidenceRequirement`

Declares an evidence type, description, minimum count, and optional fields that
must remain consistent across matching evidence items. `minimum_trust_level`
defaults to `RUNTIME_OBSERVED`; `max_age` rejects stale items. A successful
result requires an explicitly declared and satisfied `RUNTIME_OBSERVED` or
`INDEPENDENT` requirement. Agent claims, receipts, and undeclared evidence do
not supply that boundary.

### `EvidenceCollection`

Immutable, iterable collection with unique evidence IDs. It supports `get`,
`of_type`, `append`, and collection addition.

### Collector interfaces

- `EvidenceCollector`: `record(...)` and `snapshot()` protocol.
- `ObservableEvidenceCollector`: optional listener extension used for immediate
  telemetry.

Collector trust/acquisition keyword arguments remain accepted for source
compatibility, but worker-facing collectors ignore elevated selections and
record an agent claim. Use `EvidenceProviderRegistration` and
`EvidenceProviderRegistry` at the application-owned action or recovery
executor boundary to grant elevated custom-provider trust.
- `InMemoryEvidenceCollector`: thread-safe local implementation.

Built-in outcome providers are `FileEvidenceProvider`,
`CallableEvidenceProvider`, and `ActionReceiptEvidenceProvider`. The receipt
provider always produces `EXECUTOR_RECEIPT` evidence, below `INDEPENDENT`.

## Verification

### `Verifier`

```python
def verify(
    contract: TaskContract[InputT, OutcomeT],
    output: OutcomeT,
    evidence: EvidenceCollection,
) -> VerificationResult: ...
```

### `RuleBasedVerifier`

Deterministically evaluates required evidence and every declared acceptance
criterion. Built-in criteria are:

- `DeclaredConditionCriterion` / `PredicateCriterion`;
- `FieldEqualsCriterion`;
- `CollectionNotEmptyCriterion`;
- `ApprovalCriterion`;
- `RuntimeConfirmationCriterion`.

`VerificationStatus` distinguishes `verified`, `failed`, `inconclusive`,
`awaiting_evidence`, `awaiting_approval`, and
`awaiting_runtime_confirmation`.

The verifier trusts neither `WorkerReport.status` nor adapter output as proof.
It evaluates criteria only with evidence matching trustworthy declared
requirements. The runtime applies the same minimum trust-boundary check to any
injected `Verifier`, so a custom verifier cannot grant output-only success.

## Capabilities and recovery

### Capability declarations

- `CapabilityDeclaration`: name, description, availability, recovery support,
  task-state/risk limits, idempotency, approval, and runtime-confirmation flags.
- `CapabilityRegistry`: thread-safe runtime registry.
- `StandardCapability`: `checkpoint`, `resume`, `cancel`, `retry`, `rollback`,
  `inspect_health`, and `refresh_session` vocabulary.
- `standard_recovery_capabilities()`: conservative declarations, not handlers.

### Recovery models

- `RecoveryAction` and `RecoveryPlan`: exact-hashed proposals containing the
  diagnosis, context reference, capability, risk, handler identity/config,
  postcondition provider identity/config, pre/postconditions, approval
  requirement, and optional compensation identity.
- `RecoveryPolicy`: application-owned allowlist and safety limits;
  `safe_default()` denies all capabilities.
- `ApprovalRequest`, `ApprovalDecision`, `ApprovalRevocation`, and
  `ApproverIdentity`: durable exact-hash approval artifacts.
- `PreActionCapabilityConfirmation`: pre-execution capability/preflight
  observation bound to an exact action hash. `RuntimeConfirmation` is its
  compatibility alias.
- `RecoveryExecutionReceipt`: executor-reported result, not external proof.
- `RecoveryPrecondition`, `RecoveryPostcondition`, and `RecoveryCompensator`:
  application execution-boundary interfaces.
- `RecoveryResult`, `RecoveryActionResult`, `RecoveryStatus`,
  `RecoveryReason`, and `RecoveryReasonCode`: structured decisions.

### `RecoveryExecutor`

Protocol for evaluating safety gates before action execution.
`InMemoryRecoveryExecutor` is the local implementation. It invokes only
application-injected async handlers and records idempotency state in memory.

### `DurableRecoveryExecutor`

SQLite-backed recovery coordination. It executes exactly one action per plan,
persists pause/resume state, consumes exact approvals and reserves idempotency
transactionally, changes abandoned execution to `UNKNOWN`, acquires
postcondition evidence, and invokes `DurableRuntime.verify_after_recovery`.
Handlers are supplied as `RecoveryHandlerRegistration` values whose stable
identity and JSON configuration must exactly match the approved action before
execution.
Only a final `RecoveryStatus.VERIFIED` makes `RecoveryResult.succeeded` true.
See [durable approvals and recovery](approvals-and-recovery.md).

## Existing-agent adapters

### `AgentAdapter[InputT, OutcomeT]`

Protocol exposing `adapter_contract`, optional `recovery_hooks`, `submit(...)`,
and `health()`. `AgentAdapterContract` contains an `AgentIdentity`, explicit
capabilities, and evidence/recovery-hook declarations.

`AgentAdapterWorker` exposes an adapter through the native `Worker` protocol.
`FakeAgentAdapter` is intended for deterministic tests and examples.

`AdapterRecoveryHooks` may propose a `RecoveryPlan`; the proposal still passes
through the normal recovery executor gates.

### Experimental LangGraph boundary

`LangGraphRunnable` describes only an injected async `ainvoke` shape.
`LangGraphAdapterBoundary` maps invocation, output, optional evidence, health,
and recovery hooks. It imports no LangGraph package and does not implement node
tracing, checkpoint integration, or tool interception.

## Telemetry

### `LifecycleEvent` and `LifecycleEventType`

Structured, ordered task events with task/correlation/worker identity,
timestamp, sequence, current/previous state, name, and details.

### Event interfaces and implementations

- `EventSink`: synchronous `emit(event)` protocol.
- `TaskEventEmitter`: task-bound progress and tool/action emitter.
- `NullEventSink`, `InMemoryEventSink`, `JsonlEventSink`, and
  `CompositeEventSink`.
- `CallbackEventSink`: application callback adapter.
- `lifecycle_event_to_dict`: transport-safe primitive serialization.

### Optional CortexOps observation integration

`runmantle.integrations.cortexops` provides `CortexOpsIntegrationConfig`,
`CortexOpsRedactionConfig`, `CortexOpsEventSink`, and
`create_cortexops_event_sink`. Local JSONL is the default destination. The
factory adds `DurableCortexOpsOutboxExporter` unless durable delivery is
explicitly disabled; `CortexOpsDeliveryConfig` controls batches, leases,
bounded retry/jitter, and flush timeout. `delivery_status()` and
`dead_letters()` expose delivery health without event bodies.

Installing `runmantle[cortexops]` enables the real SDK exporter. An
`otlp_endpoint` is required before the factory creates a network transport.
The original root-level `CortexOpsEventTransport` and `CortexOpsEventSink`
remain generic application-owned compatibility boundaries. Neither boundary
grants authority or makes observed claims into verified outcomes. See
[the integration contract and trust boundary](cortexops.md).

### Optional CortexOps control integration

`runmantle.integrations.cortexops_control` provides
`CortexOpsControlClient`, `UrllibCortexOpsControlTransport`,
`CortexOpsControlledActionExecutor`, and
`CortexOpsControlledRecoveryExecutor`. It uses the sibling CortexOps
`/api/runmantle/v1` contract and the existing CortexOps governance policy,
one-time permit, authentication, approval, and recovery-decision stores.

The caller supplies an authorization callback; Runmantle does not read or
embed credentials. Control is synchronous and fail-closed. A transport error,
stale policy, expired permit, changed action/plan hash, unsupported capability,
`observe` mode, or `demo` data mode grants no authority. Only calls made through
the controlled wrappers are enforced. Missing, malformed, unknown, or
forward-version policy, approval, and dispatch responses fail closed. See the
[control and trust matrix](cortexops.md#control-loop-v1).

## Demo API and CLI

- `create_deterministic_demo()`: returns the packaged worker and contract.
- `run_deterministic_demo()`: executes the demo and returns `DemoRun`.
- `runmantle demo [--json]` and `python -m runmantle demo [--json]`.

The deterministic demo deliberately uses only worker-owned calculation
evidence and therefore ends at `awaiting_evidence`; use the Verified Release
Guard quickstart for an installed workflow that reaches `verified` through a
runtime-observed filesystem/Git boundary.

## Compatibility aliases

The preview retains aliases from earlier iterations: `Capability`, `Evidence`,
`SuccessCriterion`, `ContractVerifier`, `VerificationReport`, `WorkerContext`,
`WorkerRuntime`, `RunResult`, `RunStatus`, and `ErrorInfo`. New code should
prefer the primary names documented above.
