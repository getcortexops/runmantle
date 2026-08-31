# CortexOps integration

Runmantle has two separate optional CortexOps paths. The observation bridge is
disabled by default; local JSONL is its default destination and network delivery
requires an explicit OTLP endpoint. The synchronous control loop is also
disabled by default and exists only when an application constructs its client,
supplies authentication, and selects `control` + `live`. Core remains
provider-neutral and fully usable without either path.

## Install and local use

The dependency-free local path needs only Runmantle:

```python
from pathlib import Path

from runmantle.integrations.cortexops import (
    CortexOpsIntegrationConfig,
    create_cortexops_event_sink,
)

sink = create_cortexops_event_sink(
    CortexOpsIntegrationConfig(
        enabled=True,
        export_path=Path("./cortexops_runmantle_events.jsonl"),
        outbox_path=Path("./cortexops_runmantle_outbox.sqlite3"),
        project="my-project",
        environment="local",
        service_name="my-worker-service",
    )
)
```

Pass `sink` as the runtime `event_sink`. When disabled (the default), the
factory returns a no-op sink and creates no files.

The factory persists each mapped event to the SQLite outbox before delivery.
Successful local JSONL delivery remains inspectable with:

```bash
cortexops sdk events --file ./cortexops_runmantle_events.jsonl
cortexops dashboard sdk --events-file ./cortexops_runmantle_events.jsonl
```

## Explicit CortexOps OTLP delivery

Install the optional SDK and configure the existing CortexOps OTLP ingest path:

```bash
pip install 'runmantle[cortexops]'
```

```python
sink = create_cortexops_event_sink(
    CortexOpsIntegrationConfig(
        enabled=True,
        otlp_endpoint="http://127.0.0.1:8000/v1/traces",
        include_local_jsonl=True,
    )
)
```

This uses the official `cortexops-sdk` `OtlpHttpJsonExporter`. Set
`include_local_jsonl=False` to select only OTLP. Runmantle does not invent an
authentication scheme; configure a deployment-specific endpoint/transport at
the application boundary. An application may still inject an existing SDK
exporter through `create_cortexops_event_sink(..., exporter=...)`.

## Durable delivery guarantees

`DurableCortexOpsOutboxExporter` provides:

- SQLite transactions, WAL mode, a versioned schema, and event content conflict
  detection;
- stable IDs derived from task/session, lifecycle sequence/type, and timestamp;
- at-least-once delivery, bounded exponential backoff with jitter, batching,
  and restart recovery;
- expiring delivery leases so an interrupted sender can be retried;
- explicit `flush()` and `close()` bounds;
- observable counts through `CortexOpsEventSink.delivery_status()` and
  dead-letter records through `dead_letters()`.

At-least-once means duplicates are possible if the receiver accepted a batch
and the process stopped before the local acknowledgement transaction. Stable
event IDs permit receiver-side deduplication. No background thread is created:
delivery is attempted on emit and advanced by later emits or `flush()`. Offline
delivery failure never changes task execution; the event remains pending or
eventually becomes a visible dead letter. Error records store exception classes,
not response bodies that may contain credentials.

## Exported mapping

Every record uses the real CortexOps SDK `custom.event` contract and the
`runmantle.cortexops.event.v1` payload envelope.

| Runmantle concept | Exported representation |
|---|---|
| Worker | `agent_id`, identity/version/role, declared capabilities |
| Task contract | task ID plus content hashes, criteria structure, evidence requirements, capability/risk/timeout declarations |
| Lifecycle | original ordered lifecycle event and current/previous state |
| Agent report | distinct `agent.reported_completion`; never verification |
| Verified outcome | explicit `verified_outcome=true` only for a `VERIFIED` result/transition |
| Evidence | ID, computed checksum, acquisition, source, freshness, trust and redacted provenance |
| Verifier | status, missing/contradictory evidence and criterion decisions |
| Action/policy | request/hash/capability/risk, policy and authorization decisions, executor receipt metadata |
| Approval | request/decision/hash/scope/expiry/consumption/revocation state |
| Recovery | immutable plan metadata, preflight, approval, execution receipt, postcondition and final verification observations |

CortexOps' SDK OTLP exporter preserves a bounded redacted custom payload in
`cortexops.custom.payload_json`; its OTLP parser restores that payload and the
stable `cortexops.event.id`. JSONL preserves the mapped payload directly.

## Redaction

Content-bearing fields are omitted by default. `CortexOpsRedactionConfig`
provides separate opt-ins for task objectives/input, prompts, tool arguments,
outputs, evidence content, provenance values, recovery diagnoses, and arbitrary
custom details. Secret-like keys are still removed unless `include_secrets=True`
is also explicitly set. Defaults export hashes and structural metadata where
possible, not prompts, tool arguments, evidence bodies, or raw diagnoses.

The CortexOps SDK applies a second defensive redaction pass before embedding a
custom payload in OTLP and replaces payloads larger than 64 KiB with a checksum
and truncation marker. This is defense in depth, not a substitute for choosing
appropriate Runmantle redaction settings.

## Trust boundary and limitations

- Exported agent claims are observations, not verification.
- Executor and adapter receipts are not independent proof of external effects.
- Observation does not imply enforcement. Runmantle action enforcement applies
  only to calls routed through its mediated action boundary.
- Capability declarations are metadata, not CortexOps grants or authorization.
- Pre-action confirmation, execution receipt, postcondition evidence, and final
  verification remain separate events.
- The observation bridge does not mutate CortexOps Outcomes, Recovery,
  Workforce, governance, approval, or control-plane records.
- The outbox is process-safe through SQLite transactions and leases, but it is
  not a distributed exactly-once queue. It has no background scheduler,
  encryption-at-rest, remote acknowledgement protocol, or automatic dead-letter
  replay.

Cross-repository tests are explicitly marked and load the sibling CortexOps SDK
and parser directly. A standalone checkout reports those tests as skipped; the
combined-workspace CI job checks out CortexOps and requires every marked test to
pass against the real contracts. CortexOps' own tests also prove the redacted
custom envelope survives SDK-to-OTLP-to-parser ingest.

## Control loop v1

The control path reuses CortexOps' existing authentication, active policy
snapshots, deterministic tool-rule evaluator, exact action fingerprint,
one-time approval permit, governance receipt, and recovery-decision contracts.
CortexOps adds only a versioned Runmantle coordination surface for runtime/task
registration and runtime-owned recovery proposals:

```python
from runmantle.integrations.cortexops_control import (
    CortexOpsControlClient,
    UrllibCortexOpsControlTransport,
)

transport = UrllibCortexOpsControlTransport(
    "http://127.0.0.1:8000",
    authorization_provider=lambda: application_auth_header(),
)
control = CortexOpsControlClient(
    transport,
    runtime_id="payments-worker-runtime",
    runtime_version="1.4.0",
)
control.register_runtime({"charge_refund", "retry"})
```

The callback must use the existing CortexOps bearer identity configuration (or
its loopback-only local boundary). Credentials are not stored in Runmantle.
Register each task with its immutable contract hash before policy evaluation or
recovery review. Wrap consequential execution with
`CortexOpsControlledActionExecutor` or
`CortexOpsControlledRecoveryExecutor`; constructing a client alone grants no
authority and intercepts nothing.

Control requests are synchronous by design. They have stable request/message
IDs and CortexOps stores idempotency responses, but they are not queued in the
telemetry outbox. If CortexOps cannot return an authoritative answer, a
controlled consequential action remains blocked. An execution receipt that
cannot be delivered never changes the task to `VERIFIED`.

### Capability and trust matrix

| Path or signal | CortexOps role | Authority / proof | Offline behavior |
|---|---|---|---|
| Local JSONL / OTLP lifecycle export | Observe | Observation only; no control | Task continues; durable telemetry outbox retries |
| `observe` registration | Observe | May register/synchronize task observations; cannot evaluate or dispatch | No authority |
| `demo` registration | Demo isolation | Never control authority, even with `mode="control"` | No authority |
| `control` + `live` runtime handshake | Control | Binds authenticated principal, runtime ID, declared capabilities, active policy hash | No handshake means no controlled action |
| Task registration/status sync | Observe/control | Runtime-authored status; only a Runmantle `verified` message carries a verification hash; verified status cannot be downgraded | No optimistic CortexOps mutation |
| Mediated action evaluation | Control | Deterministic CortexOps policy decision over hashed arguments and runtime-supplied redacted facts | Fail closed |
| Approval decision | Control | Authenticated operator, exact action fingerprint/hash, current policy, expiring one-time permit | No approval |
| Dispatch | Control | Consumes the exact permit before local handler execution | Handler is not invoked |
| Executor receipt | Observe/control | Proves only that the bound runtime reported an execution result; not an independent postcondition | Remains locally non-verified; retry delivery explicitly |
| Post-action runtime confirmation | Observe/control | An explicit adapter queries the target after execution and reports observed/expected state plus evidence references; it is distinct from preflight and receipts | Inconclusive when the probe cannot establish state; never causes a second execution |
| Recovery review/instruction | Control | Exact plan/action hashes, capability, risk, active policy, reviewer, and short expiry | Recovery is not executed |
| Recovery postcondition evidence | Runmantle verification | Application/provider-acquired evidence; trust depends on provider and provenance | No final success without evidence |
| Final `VERIFIED` outcome | Runmantle authority | Deterministic contract verification is authoritative for task success | Network state cannot manufacture success |
| Direct unrestricted Python side effect | Outside boundary | Neither observed nor prevented unless application routes it through mediation | Not enforceable |

### Guarantees and current limits

- A runtime ID is bound to its authenticated principal. Its `demo/live` data
  mode is immutable; use a different runtime ID to separate data paths.
- A task must be registered and action correlation/worker identity must match
  that registration. Capabilities outside the handshake are rejected.
- To preserve argument redaction, Runmantle sends the input hash plus typed,
  content-minimized rule facts. CortexOps validates complete ordered coverage
  and internal consistency against the active policy, but it cannot independently
  recompute string/glob matches without raw arguments. The authenticated runtime
  remains inside that policy-fact trust boundary.
- Policy versions, approvals, dispatch permits, and recovery instructions are
  checked again at use time. Changed policy, expired authority, or mismatched
  hashes fail closed.
- A controlled action persists its local receipt before it is submitted to
  CortexOps. If receipt delivery fails, a subsequent call with the same action
  identity replays delivery from that durable record and the mediated executor
  prevents another handler invocation. A post-action provider is optional and
  must be explicitly installed; it queries the target rather than trusting the
  handler or receipt. CortexOps retains that observation separately and returns
  a reported state, but does not treat it alone as task verification.
- Action evaluation accepts only the exact v1 `ALLOW`, `BLOCK`, and
  `REQUIRE_APPROVAL` response shapes. Only `ALLOW`, or a complete approved
  response whose one-time permit is confirmed consumed by a valid
  `DISPATCHED` acknowledgement, can reach the local handler. Missing, malformed,
  unknown, or forward-version decision/dispatch values fail closed.
- Runtime control messages and receipts are idempotent. Consequential local
  execution remains protected independently by Runmantle's durable idempotency
  state. Concurrent duplicate inbox messages for one local CortexOps database
  are serialized across threads (and across POSIX processes) through one
  critical section covering the lookup, domain mutation, and stored response;
  replay returns that persisted response. This is local coordination, not a
  distributed exactly-once protocol.
- CortexOps does not optimistically mutate incidents, Workforce records, or the
  Runmantle task. Its coordination tables change only from runtime status,
  authenticated operator decisions, and runtime receipts.

### Local end-to-end fixture

The checked-in controlled-deployment fixture starts the real sibling CortexOps
HTTP process, obtains an operator approval, executes once, submits the durable
receipt, and has an independent `/health` + `/version`-style provider submit a
post-action confirmation:

```bash
RUNMANTLE_CORTEXOPS_PROCESS_TEST=1 CORTEXOPS_REPOSITORY=/path/to/cortexops \
  ./.venv/bin/python -m pytest -q tests/test_cortexops_process_integration.py
```

It is a local fixture, not a production deployment. The provider intentionally
supplies the target observation; applications must replace it with an adapter
that queries their actual runtime.

### Separate-process compatibility test

`RUNMANTLE_CORTEXOPS_PROCESS_TEST=1 pytest -q
tests/test_cortexops_process_integration.py` starts the checked-out sibling
CortexOps routers under Uvicorn in a separate process. It uses configured
runtime/operator bearer identities, the Runmantle urllib HTTP transport,
runtime and task registration, live policy evaluation, operator approval, one
controlled action/receipt, and verified-status synchronization. It is opt-in
and reports an explicit skip when the sibling checkout or local service
environment is unavailable. This local test covers real HTTP and auth without
TLS; it does not claim TLS termination, reverse-proxy, container-orchestrator,
or remote-network coverage.
- This first loop polls approval/recovery state; it has no push channel,
  background policy stream, distributed control outbox, TLS, or hosted identity
  service. CortexOps' documented local authentication and deployment limits
  still apply.
