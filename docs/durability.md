# Durable local execution

`DurableRuntime` is Runmantle's single-node, local-first execution runtime. Its
default `SQLiteStore` records all authoritative state in one database without
pickle or executable deserialization.

The default `SafeJsonCodec` rejects documents over 8 MiB, structures over 64
levels deep, and documents containing over 100,000 collection entries. These
limits are configurable when an application deliberately supplies its own
codec to `SQLiteStore`.

## Persisted records

The schema stores:

- a safe contract snapshot and its SHA-256 digest;
- authoritative task state and optimistic version;
- worker-reported status separately from verification status;
- reported output and structured errors;
- evidence and complete ordered lifecycle history;
- idempotency reservations and results;
- explicit checkpoints;
- exact-hash approval requests, authenticated-boundary decisions, revocations,
  expiration, and one-time consumption;
- pre-action capability confirmations and complete recovery-plan state;
- mediated action requests, policy decisions, authorizations, execution owner,
  receipts, durable postcondition phase, and postcondition evidence links.

SQLite foreign keys are enabled on every connection. File databases use WAL,
`synchronous=NORMAL`, `BEGIN IMMEDIATE` write transactions, and a configurable
busy timeout. Each lifecycle transition checks the expected task version and
commits its state and transition event atomically. Event sequence numbers are
allocated inside that write transaction.

Schema migrations are monotonic and recorded in both `PRAGMA user_version` and
`schema_migrations`. Runmantle refuses to open a database newer than its latest
supported schema. Version 1 through 6 databases migrate to version 7 without
replacing task, evidence, event, or idempotency rows. Version 3 recalculates
legacy evidence checksums, adds default acquisition/trust metadata, updates
contract snapshots, and installs evidence immutability triggers. Version 4
adds exact approval bindings, identity/decision/revocation/use fields, recovery
execution ownership and receipts, and recovery-evidence links. Legacy approvals
are preserved under `legacy.approval`, marked with an unverified legacy issuer,
and receive no new capability scope.
Version 5 adds established evidence-origin metadata and conservatively
downgrades all pre-v5 evidence because its acquisition authority cannot be
proven. Evidence-dependent legacy verified tasks become `INCONCLUSIVE`.
Version 6 adds the ordinary-action postcondition phase. Existing successful
executor receipts migrate conservatively to `pending`, so their declared
postconditions are reacquired on the next exact action resume without repeating
the handler.
Version 7 binds action authorization to the task execution context, adds
explicit postcondition completion markers, and revalidates legacy `VERIFIED`
rows against the trusted-evidence commit invariant. Rows that cannot establish
that invariant become `INCONCLUSIVE` for re-verification.

## Resume behavior

The safe resume boundary depends on persisted state:

| State | Resume behavior |
|---|---|
| `PENDING` | Atomically claims `RUNNING`, then invokes the supplied worker once |
| `RUNNING` | Requires a committed checkpoint and `CheckpointedWorker.resume` |
| `AGENT_REPORTED_COMPLETE` | Runs verification; never treats the report as success |
| `VERIFYING` | Re-runs deterministic verification after a prior process stop |
| `AWAITING_EVIDENCE` | Continues only after the durable evidence count changes |
| `AWAITING_APPROVAL` | Continues only after a durable approval decision changes |
| `AWAITING_RUNTIME_CONFIRMATION` | Continues only after a confirmation is added |
| `INCONCLUSIVE` | Re-enters `VERIFYING` so new evidence or verifier conditions can be evaluated |
| `VERIFIED` / `FAILED` | Returns the stored result without new events or effects |

Repeated resume calls cannot reclaim a pending execution, repeat a claimed
checkpoint, or append terminal events. A `RUNNING` task with no checkpoint is
never executed again blindly. If an older checkpoint exists, continuation
starts from that explicit boundary; external actions performed after it can be
retried and therefore still require application-level idempotency.

SQLite serializes competing resume claims, but it does not lease a live worker
or prove that the original process has stopped. Applications must not resume a
`RUNNING` task while its original worker may still be active. A crash after a
checkpoint claim leaves that claim reserved for operator reconciliation rather
than silently executing it again.

An ordinary mediated action commits executor success and
`postcondition_status=pending` in one transaction. Resuming that exact action
never reinvokes the handler: it acquires only postconditions without persisted
completion markers, atomically persists each complete evidence batch with its
links and marker, then marks the phase `completed`. Required postcondition
failures leave it pending for an explicit retry.

Lifecycle export is not authoritative storage. `BufferedEventSink` adds a
bounded queue with explicit block, raise, or drop policies plus bounded
`flush()` and `close()`. Dropped or failed export is observable, while the
ordered event remains committed in SQLite.

## Checkpoints are explicit

Workers save a checkpoint with `TaskContext.save_checkpoint(...)` at a boundary
chosen by application code. The task and worker must both allow the
`checkpoint` capability. The payload must contain every piece of state the
worker's `resume(...)` method requires.

Runmantle does not serialize Python call stacks, suspended coroutines, closures,
open file descriptors, network sessions, locks, or uncommitted transactions.
It cannot continue halfway through an arbitrary Python function.

## Serialization guarantees

`SafeJsonCodec` accepts JSON primitives and containers plus explicitly tagged
bytes, timezone-aware datetimes, timedeltas, and paths. Dataclasses become
plain objects. It rejects non-finite floats, non-string mapping keys, naive
datetimes, arbitrary class instances, and invalid tagged values. The
`$runmantle_type` object key is reserved for these tagged values.

Contract snapshots describe callable criteria by identity but never persist or
load their executable code. The application must supply the executable contract
again for resume; its safe snapshot digest must match. Applications using
callable criteria should include an explicit contract revision in metadata,
because changing a function body without changing its identity is not
detectable from safe JSON alone.

## Guarantees and limitations

Runmantle guarantees within one supported SQLite filesystem:

- only `VERIFIED` makes `TaskResult.succeeded` true;
- `VERIFIED` requires at least one satisfied, explicitly declared
  `RUNTIME_OBSERVED` or `INDEPENDENT` evidence requirement, including when an
  application injects a custom verifier;
- invalid lifecycle transitions roll back without an event;
- conflicting task versions reject one writer;
- contract snapshots are checksum-validated when loaded;
- duplicate evidence, checkpoint, approval, confirmation, and resume IDs are
  idempotent only when their persisted content agrees;
- mediated actions persist before invocation and reserve their idempotency key;
- an action abandoned by a prior executor instance becomes `UNKNOWN`, never
  successful and never automatically retried;
- persisted evidence content cannot be updated or deleted;
- exact approval requests are immutable and one-time grants are consumed in the
  same transaction that claims action or recovery execution;
- durable recovery reserves idempotency before invocation, never re-executes an
  abandoned claim, and re-runs task verification only after postconditions;
- verification inputs cannot be appended after a task reaches `VERIFIED`;
- internal event history survives restart and remains strictly ordered.

It does not provide distributed consensus, network-filesystem correctness,
database encryption, automatic backups, trusted approver authentication,
independent proof of external effects, or exactly-once semantics in external
systems. External actions still need application idempotency keys and
independent verification. The optional event sink runs after the internal
commit; the SQLite history is authoritative if external publication fails.

`DurableRecoveryExecutor` coordinates local restart-safe recovery, but the
application still owns handlers, authentication, external idempotency, and
postcondition providers. `InMemoryRecoveryExecutor` remains as a non-durable
compatibility implementation.
