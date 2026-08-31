# Mediated actions and evidence

Runmantle enforces capability and policy checks only for actions routed through
`MediatedActionExecutor` or `SafeFunctionTool`. It does not sandbox a worker and
cannot prevent unrestricted Python, a third-party agent, or an adapter from
performing side effects directly. Applications that need these guarantees must
expose consequential tools only through the mediated boundary and keep direct
credentials and clients out of worker reach.

## Decision artifacts

The action flow deliberately keeps these records separate:

1. `ActionRequest`: the agent or application claims that an action should run;
2. `ActionPolicyDecision`: capability, task state, risk, and application policy;
3. `PreActionAuthorization`: persisted approval and preconditions;
4. `ActionReceipt`: what the executor reports about its invocation;
5. runtime state: durable execution observations, including `UNKNOWN`;
6. outcome evidence: postcondition observations acquired after execution;
7. verified outcome: the task verifier's decision. Only `VERIFIED` succeeded.

An `EXECUTOR_SUCCEEDED` receipt is not independent proof of delivery,
settlement, persistence, or any other external effect. `ActionExecutionResult`
therefore exposes `executor_succeeded`, while `verified_outcome` never infers
success from the receipt.

## Capability matrix

| Control | Mediated actions | Direct unrestricted Python | Guarantee |
|---|---:|---:|---|
| Task capability allowlist | Enforced | Not enforced | Missing capability fails closed before handler invocation |
| Runtime capability registry | Enforced | Not enforced | Capability must be registered, available, state-compatible, and within its risk limit |
| Application `ActionPolicy` | Enforced | Not enforced | Deny-by-default capability, task-state, and risk checks |
| Exact pre-action approval | Enforced when configured | Not enforced | Approval key is bound to the action hash |
| Preconditions | Enforced | Not enforced | Exceptions and false results deny authorization |
| Persist-before-execute | Enforced by SQLite transaction | Not applicable | `EXECUTING` and its lifecycle event commit before the handler starts |
| Idempotency after success | Enforced per task/capability/key | Not enforced | Duplicate calls return persisted state without invoking the handler |
| In-flight duplicate | Owner-aware | Not enforced | Same executor instance observes the active action without re-execution |
| Restarted in-flight action | Fail closed | Not enforced | A different executor instance changes abandoned `EXECUTING` to `UNKNOWN` without retry |
| Timeout/cancellation after start | Conservative | Not enforced | Status is `UNKNOWN`, because partial external effects may exist |
| Dry run | Enforced | Not applicable | Authorization runs, handler does not, and the live idempotency key remains available |
| Executor receipt | Persisted and hashed | Application-defined | Records the executor claim; never grants task verification |
| Postcondition acquisition | Supported | Application-defined | Providers run after executor-reported success |
| Task verification | Separate verifier gate | Separate verifier gate | Only `TaskStatus.VERIFIED` is success |

## Function tools

`SafeFunctionTool` adapts a synchronous or asynchronous Python callable. Native
workers and adapter-backed workers call `invoke(...)` with their `TaskContext`,
contract, arguments, and stable idempotency key. The wrapper passes the
context's intersected capability set and cancellation token to the executor.

```python
executor = MediatedActionExecutor(
    store=runtime.store,
    capabilities=capability_registry,
    policy=ActionPolicy(allowed_capabilities={"deploy.release"}),
)

deploy = SafeFunctionTool(
    name="deploy-release",
    description="Deploy one immutable release.",
    required_capability="deploy.release",
    function=deploy_release,
    executor=executor,
    risk_level=RiskLevel.HIGH,
    postconditions=(
        Postcondition(
            name="observe-release",
            description="Read release state independently.",
            provider=release_state_provider,
            evidence_type="release_state",
        ),
    ),
)
```

For high-risk actions, keep the handler narrow, make the external API
idempotent using the same key, and acquire postconditions from a different read
path or authority where practical.

## Durable action semantics

SQLite schema version 7 stores requests, hashes, policy decisions,
authorizations, runtime owner, receipts, a durable postcondition phase, and
explicit per-postcondition completion markers. Action state and its lifecycle
event commit together under optimistic locking.

The idempotency scope is `(task_id, required_capability, idempotency_key,
dry_run)`. Reusing it with different action content is rejected. Dry-run and
live execution use separate records.

The executor instance ID distinguishes a duplicate call handled by the same
live executor from an action found by a later process. Runmantle does not use a
distributed lease and cannot prove process death. Give each live executor a
unique ID and do not intentionally reuse it after restart.

When an exact approval is required but absent, action state becomes
`AWAITING_APPROVAL`. Calling the executor again after persisting a decision
re-evaluates authorization on the same action record and idempotency key. A
rejected approval becomes `BLOCKED`; neither state invokes the handler.
The pending `ApprovalRequest` uses `ActionRequest.approval_id`, is bound to the
exact action hash and capability scope, expires, and is consumed once in the
same transaction that moves the action to `EXECUTING`. The legacy
`ApprovalRecord` projection remains available for compatibility. See
[durable approvals and recovery](approvals-and-recovery.md).

### Approval-bound action manifest

`ActionRequest.action_hash` is SHA-256 over canonical safe JSON containing the
manifest version, task ID, action name, capability, calculated input hash,
idempotency key, risk, requester, explicit execution-handler identity, complete
metadata, timeout, precondition descriptions and evaluator identities, and
postcondition descriptions, required flags, evidence types, provider identities
and provider configurations. `ApprovalRequest` separately binds the action ID,
that action hash, and exact capability execution scope.

The request timestamp is not execution semantics; the approval request binds
its own immutable creation and expiration. An alternate action ID resolves to
an existing action only when the scoped idempotency key and full action hash
match. Approval-requiring direct callers must supply a stable, versioned
`execution_handler_id`; built-in wrappers derive one from source identity.
Dataclass provider configuration is derived from stable JSON fields and callable
identity, while custom providers should declare explicit security-relevant
identity/configuration. These values detect declared changes; they are not code
signing or proof of deployed binary provenance.

A required postcondition that raises, returns the wrong evidence type, or
returns zero evidence emits `action.postcondition_failed` and fails the worker
boundary. The executor receipt remains recorded, but that result cannot
silently continue toward `VERIFIED`.

Executor success atomically enters the `pending` postcondition phase. A later
process resumes that phase without calling the handler again, skips
postconditions with explicit durable completion markers, and atomically stores
each provider's complete evidence batch, links, and marker. It records the
overall phase as `completed` only after all required acquisitions succeed. A
crash during a provider call may repeat that observation, so providers must
remain safe to read repeatedly; it never repeats the consequential action.

## Evidence integrity and trust

`EvidenceItem` calculates its canonical SHA-256 checksum from content and
payload. A supplied checksum is only an assertion and is rejected if it
differs. Payload, provenance, and metadata are recursively frozen in memory.
SQLite schema version 3 rejects updates and deletes after persistence.

Every item records source, acquisition method, collection timestamp, claimed
trust level, provenance, and optional expiry. Elevated evidence also records a
framework-established `trust_origin`, including the acquisition boundary,
stable provider identity/configuration, and an origin hash. The verifier uses
`effective_trust_level`, not a caller-selected enum. `EvidenceRequirement` can
set `minimum_trust_level` and `max_age`; its default minimum is
`RUNTIME_OBSERVED`. Successful verification requires at least one explicitly
declared requirement at that level or stronger. Evidence below its effective
trust level, future-dated, expired, undeclared, or too old is unavailable to
verification. `AGENT_CLAIM` and `EXECUTOR_RECEIPT` can remain auditable context
but cannot independently prove the outcome.

| Trust level | Intended meaning |
|---|---|
| `UNTRUSTED` | Unclassified input that should not satisfy normal requirements |
| `AGENT_CLAIM` | Evidence reported by the worker or adapter itself |
| `EXECUTOR_RECEIPT` | Receipt reported by the action executor |
| `RUNTIME_OBSERVED` | State observed by application/runtime-owned code |
| `INDEPENDENT` | Observation acquired through a deliberately independent source |

Worker-facing collectors retain the old trust/acquisition keyword arguments
for source compatibility but always store worker submissions as
`AGENT_REPORTED` / `AGENT_CLAIM`. Manually constructing an `EvidenceItem` with
`INDEPENDENT` records only a claim: without a framework-established origin its
effective trust is capped at `AGENT_CLAIM`.

Elevated trust has only two paths. Exact built-in providers invoked by the
mediated action boundary receive their fixed classification
(`ActionReceiptEvidenceProvider` is `EXECUTOR_RECEIPT` and
`FileEvidenceProvider` is `RUNTIME_OBSERVED`). Application providers must be
registered by exact provider instance in an application-owned
`EvidenceProviderRegistry`, with a stable identity, complete security-relevant
JSON configuration, acquisition method, and assigned trust level. An
unregistered custom provider is downgraded to an agent claim even when its
returned object asks for higher trust. Registration says the application owns
that acquisition boundary; it is not remote attestation, credential isolation,
or proof that a mislabeled source is genuinely independent.
Executors seal the supplied registry at construction, so worker-time code
cannot add a new trust grant. Evidence returned directly in a `WorkerReport` or
passed to `DurableRuntime.add_evidence(...)` is always reclassified as an agent
claim; trusted provider output enters persistence directly from the mediated
action or recovery boundary.

Built-in providers are deliberately small:

- `FileEvidenceProvider` reads file existence, bytes, size, and SHA-256;
- `CallableEvidenceProvider` adapts application-owned observation code and
  requires explicit registration for elevated trust;
- `ActionReceiptEvidenceProvider` converts the receipt to
  `EXECUTOR_RECEIPT` evidence and never upgrades it to independent proof.

## Remaining limits

The local executor provides local at-most-once invocation after its durable
claim, not exactly-once external effects. It does not provide operating-system sandboxing, credential
isolation, distributed locks, remote attestation, trusted time, exactly-once
external effects, automatic reconciliation of `UNKNOWN`, or proof that a
callable provider is independent. Timeout or cancellation after invocation
begins is `UNKNOWN`, because the external system may already have accepted part
of the action.
