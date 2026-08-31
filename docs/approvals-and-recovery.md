# Durable approvals and recovery

Runmantle persists approvals and recovery coordination in the same local
SQLite store as task state. Executable handlers, preconditions, providers, and
verifiers are never deserialized; the application supplies the same executable
`TaskContract` and `RecoveryPlan` again after restart, and their safe snapshots
must match.

## Exact approvals

`ApprovalRequest` contains an approval ID, task ID, target ID and hash, required
scope, risk, reason, creation and expiration timestamps, one-time-use flag, and
safe metadata. `request_hash` is calculated over every immutable field.

`ApprovalDecision` must repeat that exact request hash and contains a decision
ID, decision, reason, timestamp, metadata, and `ApproverIdentity`. The identity
is an assertion supplied by the application's authentication boundary;
Runmantle persists it but does not authenticate users, validate MFA, or issue
identity tokens.

Approvals can be rejected, expire, or be revoked with `ApprovalRevocation`.
One-time grants are consumed transactionally with the action/recovery execution
claim. A grant for one action or plan cannot authorize changed parameters,
capability, risk, preconditions, postconditions, scope, or target hash.

The older `DurableRuntime.request_approval(...)` and `decide_approval(...)`
methods remain available. They create non-expiring, reusable records with scope
`legacy.approval` and identify string approvers as `legacy-unverified`. New code
should use `create_approval_request`, `record_approval_decision`, and
`revoke_approval` with the typed models.

## Recovery state machine

`DurableRecoveryExecutor` supports one consequential recovery action per plan:

```text
planned
  -> awaiting_preflight_confirmation
  -> awaiting_approval
  -> authorized
  -> executing
  -> executor_succeeded
  -> postconditions_satisfied
  -> verified
```

Any policy/precondition failure closes the plan as `blocked`. A handler error
or process loss after execution starts is `unknown`, because an external effect
may have occurred. Required postcondition acquisition failure is
`postcondition_failed`. These states never optimistically mutate the original
task.

Before invoking a handler, Runmantle checks the authoritative task state,
contract capability allowlist, runtime capability registry, policy allowlist,
risk limits, idempotency key, exact preflight confirmation, deterministic
preconditions, and exact active approval. The SQLite transaction that changes
the plan to `executing` also consumes its approval and reserves its idempotency
key.

After an executor-reported success, every required `RecoveryPostcondition`
must acquire evidence. Only then does `DurableRuntime.verify_after_recovery`
move the original task to `VERIFYING` and re-run its declared verifier. Only a
task result of `VERIFIED` makes `RecoveryResult.succeeded` true.

The original task remains at its failed or incomplete state while the recovery
record is paused. If a process stops after the successful executor receipt was
committed, the next process resumes at postcondition acquisition; it does not
re-run pre-action gates, consume another approval, or invoke the handler again.

## Four different meanings

| Artifact | Timing | What it establishes | What it does not establish |
|---|---|---|---|
| `PreActionCapabilityConfirmation` | Before execution | The application runtime reports support and preflight safety for an exact action hash | That execution occurred |
| `RecoveryExecutionReceipt` | After handler return | The executor reports its local result | External state or final success |
| `PostActionRuntimeConfirmation` | After action or recovery execution | An explicit adapter observed target state and attached evidence references | That the receipt itself proved the target state, or that every task criterion passed |
| `RecoveryPostcondition` evidence | After execution | A provider observed a declared external condition | All task acceptance criteria |
| Task verification | Last | The contract's evidence and criteria passed | Exactly-once behavior in an external system |

`RuntimeConfirmation` remains a compatibility alias for
`PreActionCapabilityConfirmation`. Likewise,
`requires_runtime_confirmation` remains as the constructor field on capability
and recovery policy models; use the read-only
`requires_pre_action_confirmation` property in new code. Task-level
`AWAITING_RUNTIME_CONFIRMATION` and `RuntimeConfirmationCriterion` remain for
backward compatibility with existing verification contracts.

## Approved execution manifest

The plan and approval hashes bind the recovery action capability, parameters,
idempotency key, stable handler identity, and handler configuration. They also
bind each required postcondition's name, evidence type, required flag, stable
provider identity, and provider configuration. Immediately before execution,
`DurableRecoveryExecutor` compares the approved action to its
`RecoveryHandlerRegistration` and recomputes provider identity/configuration.
Any mismatch fails closed before the handler runs; the application must submit
and approve a new plan.

Handler and provider identities are stable application/version strings or
source-semantic callable identities, never object addresses. Configuration is
safe JSON and must include every setting that can change side effects or
verification meaning: endpoint/environment, tenant, operation mode, artifact
scope, query/check version, and similar values. Dataclass providers derive this
snapshot from comparison fields; opaque providers should declare explicit
identity/configuration and be registered by exact instance. Runtime clients,
credentials, clocks, and caches should be non-comparison fields when they do
not alter semantics.

## Compensation

`RecoveryCompensator` is an optional application interface and
`RecoveryPlan.compensation_id` records its stable identity. Runmantle never
invokes compensation automatically: the application must create and approve a
separate exact plan, because blindly compensating an unknown action can cause a
second harmful side effect.

## Limits

- SQLite provides local single-node coordination, not distributed consensus.
- A process crash after invocation begins cannot prove whether the external
  effect happened; the plan remains `UNKNOWN` and is not automatically retried.
- Application handlers and providers must implement their own external-system
  idempotency and authentication.
- Callable and provider identities in a plan hash detect declared/code-identity
  changes where Python source is inspectable; they are not code signing or a
  trusted deployment mechanism. The application must re-supply trusted code.
- Runmantle cannot prevent recovery effects performed outside its mediated
  boundary.
- Approval expiration defaults are chosen by the caller. The bundled action and
  recovery helpers currently create one-day requests.
