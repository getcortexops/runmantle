"""Structured lifecycle events and transport-neutral telemetry sinks."""

from __future__ import annotations

import hashlib
import json
import queue
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from enum import Enum, StrEnum
from pathlib import Path
from threading import Condition, Lock, Thread
from typing import Any, Protocol

from ._validation import require_aware, require_non_empty_attributes
from .capabilities import CapabilityDeclaration
from .contracts import TaskContract, TaskStatus
from .serialization import SafeJsonCodec, SerializationError


class LifecycleEventType(StrEnum):
    STATE_TRANSITION = "task.state_transition"
    TASK_STARTED = "task.started"
    WORKER_STARTED = "worker.started"
    WORKER_COMPLETED = "worker.completed"
    WORKER_FAILED = "worker.failed"
    TASK_PROGRESS = "task.progress"
    TOOL_ACTION_REQUESTED = "tool_action.requested"
    EVIDENCE_COLLECTED = "evidence.collected"
    AGENT_REPORTED_COMPLETION = "agent.reported_completion"
    VERIFICATION_RESULT = "verification.result"
    RECOVERY_REQUESTED = "recovery.requested"
    RECOVERY_BLOCKED = "recovery.blocked"
    RUNTIME_CONFIRMATION_RECEIVED = "runtime.confirmation_received"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RECEIVED = "approval.received"
    APPROVAL_REVOKED = "approval.revoked"
    APPROVAL_CONSUMED = "approval.consumed"
    CHECKPOINT_SAVED = "checkpoint.saved"
    TASK_RESUMED = "task.resumed"
    ACTION_REQUESTED = "action.requested"
    ACTION_POLICY_DECIDED = "action.policy_decided"
    ACTION_AUTHORIZED = "action.authorized"
    ACTION_AWAITING_APPROVAL = "action.awaiting_approval"
    ACTION_BLOCKED = "action.blocked"
    ACTION_EXECUTION_STARTED = "action.execution_started"
    ACTION_EXECUTOR_SUCCEEDED = "action.executor_succeeded"
    ACTION_EXECUTION_FAILED = "action.execution_failed"
    ACTION_EXECUTION_UNKNOWN = "action.execution_unknown"
    ACTION_DUPLICATE_PREVENTED = "action.duplicate_prevented"
    ACTION_DRY_RUN_COMPLETED = "action.dry_run_completed"
    ACTION_POSTCONDITION_EVIDENCE = "action.postcondition_evidence"
    ACTION_POSTCONDITION_FAILED = "action.postcondition_failed"
    ACTION_POSTCONDITIONS_COMPLETED = "action.postconditions_completed"
    RECOVERY_AWAITING_APPROVAL = "recovery.awaiting_approval"
    RECOVERY_PREFLIGHT_CONFIRMED = "recovery.preflight_confirmed"
    RECOVERY_EXECUTION_STARTED = "recovery.execution_started"
    RECOVERY_EXECUTOR_SUCCEEDED = "recovery.executor_succeeded"
    RECOVERY_EXECUTION_FAILED = "recovery.execution_failed"
    RECOVERY_EXECUTION_UNKNOWN = "recovery.execution_unknown"
    RECOVERY_POSTCONDITION_EVIDENCE = "recovery.postcondition_evidence"
    RECOVERY_POSTCONDITION_FAILED = "recovery.postcondition_failed"
    RECOVERY_OUTCOME_VERIFIED = "recovery.outcome_verified"
    RECOVERY_DUPLICATE_PREVENTED = "recovery.duplicate_prevented"
    RECOVERY_CONFIRMED = "recovery.confirmed"
    TASK_FAILED = "task.failed"
    WORKER_EVENT = "worker.event"


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    """One ordered, structured event associated with a task execution."""

    event_type: LifecycleEventType
    task_id: str
    correlation_id: str
    worker_id: str
    occurred_at: datetime
    sequence: int
    state: TaskStatus
    previous_state: TaskStatus | None = None
    name: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("task_id", "correlation_id", "worker_id"),
            prefix="event",
        )
        require_aware(self.occurred_at, "event timestamp must be timezone-aware")
        if self.sequence < 1:
            raise ValueError("event sequence must be positive")
        object.__setattr__(self, "details", dict(self.details))


class EventSink(Protocol):
    """Boundary for lifecycle event delivery."""

    def emit(self, event: LifecycleEvent) -> None:
        """Publish one event."""


class EventBackpressureError(RuntimeError):
    """Raised when a bounded event sink cannot accept another event."""


class BackpressurePolicy(StrEnum):
    BLOCK = "block"
    RAISE = "raise"
    DROP = "drop"


class BufferedEventSink:
    """Bounded asynchronous wrapper with explicit flush and close semantics.

    This sink is for non-authoritative export. Durable lifecycle state is committed
    before sinks are called, so dropping an export never deletes runtime history.
    """

    def __init__(
        self,
        sink: EventSink,
        *,
        max_queue_size: int = 1_000,
        policy: BackpressurePolicy = BackpressurePolicy.BLOCK,
        emit_timeout_seconds: float = 1.0,
    ) -> None:
        if max_queue_size < 1 or emit_timeout_seconds <= 0:
            raise ValueError("event queue size and timeout must be positive")
        self.sink = sink
        self.policy = BackpressurePolicy(policy)
        self.emit_timeout_seconds = emit_timeout_seconds
        self._queue: queue.Queue[LifecycleEvent | None] = queue.Queue(max_queue_size)
        self._condition = Condition()
        self._pending = 0
        self._dropped = 0
        self._closed = False
        self._failure: Exception | None = None
        self._thread = Thread(
            target=self._drain,
            name="runmantle-event-sink",
            daemon=True,
        )
        self._thread.start()

    @property
    def dropped_events(self) -> int:
        with self._condition:
            return self._dropped

    @property
    def last_failure(self) -> Exception | None:
        with self._condition:
            return self._failure

    def emit(self, event: LifecycleEvent) -> None:
        with self._condition:
            if self._closed:
                raise EventBackpressureError("event sink is closed")
            self._pending += 1
            try:
                if self.policy is BackpressurePolicy.BLOCK:
                    self._queue.put(event, timeout=self.emit_timeout_seconds)
                elif self.policy is BackpressurePolicy.RAISE:
                    self._queue.put_nowait(event)
                else:
                    try:
                        self._queue.put_nowait(event)
                    except queue.Full:
                        self._pending -= 1
                        self._dropped += 1
                        self._condition.notify_all()
            except queue.Full as error:
                self._pending -= 1
                self._condition.notify_all()
                raise EventBackpressureError("event sink queue is full") from error

    def flush(self, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("flush timeout must be positive")
        import time

        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EventBackpressureError("event sink flush timed out")
                self._condition.wait(remaining)
            failure = self._failure
        flush = getattr(self.sink, "flush", None)
        if callable(flush):
            flush()
        if failure is not None:
            raise EventBackpressureError(
                f"downstream event sink failed: {type(failure).__name__}"
            ) from failure

    def close(self, *, timeout_seconds: float = 5.0) -> None:
        with self._condition:
            if self._closed:
                return
        failure: Exception | None = None
        try:
            self.flush(timeout_seconds=timeout_seconds)
        except Exception as error:  # noqa: BLE001 - still release worker thread
            failure = error
        with self._condition:
            self._closed = True
        try:
            self._queue.put(None, timeout=timeout_seconds)
        except queue.Full:
            failure = failure or EventBackpressureError(
                "event sink could not enqueue its close signal"
            )
        self._thread.join(timeout_seconds)
        if self._thread.is_alive() and failure is None:
            failure = EventBackpressureError("event sink thread did not stop")
        close = getattr(self.sink, "close", None)
        if callable(close):
            try:
                close()
            except Exception as error:  # noqa: BLE001 - preserve cleanup outcome
                failure = failure or error
        if failure is not None:
            raise failure

    def __enter__(self) -> BufferedEventSink:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _drain(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                self._queue.task_done()
                return
            try:
                self.sink.emit(event)
            except Exception as error:  # noqa: BLE001 - observable export failure
                with self._condition:
                    self._failure = error
            finally:
                with self._condition:
                    self._pending -= 1
                    self._condition.notify_all()
                self._queue.task_done()


class TaskEventEmitter(Protocol):
    """Task-bound emitter exposed to workers and agent adapters."""

    def emit(
        self,
        name: str,
        details: Mapping[str, Any] | None = None,
        *,
        event_type: LifecycleEventType = LifecycleEventType.TASK_PROGRESS,
    ) -> None:
        """Emit progress or a tool/action request for the current task."""


class NullEventSink:
    def emit(self, event: LifecycleEvent) -> None:
        del event


@dataclass(slots=True)
class InMemoryEventSink:
    """Thread-safe event sink for embedded runtimes and deterministic tests."""

    _events: list[LifecycleEvent] = field(default_factory=list, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def emit(self, event: LifecycleEvent) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[LifecycleEvent, ...]:
        with self._lock:
            return tuple(self._events)


@dataclass(slots=True)
class JsonlEventSink:
    """Append structured lifecycle events to one local JSONL file."""

    path: str | Path
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if not self.path.parent.exists():
            raise ValueError("JSONL sink parent directory must already exist")

    def emit(self, event: LifecycleEvent) -> None:
        line = json.dumps(
            lifecycle_event_to_dict(event),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock, Path(self.path).open("a", encoding="utf-8") as stream:
            stream.write(line)
            stream.write("\n")


class CortexOpsEventTransport(Protocol):
    """Transport supplied by an application once a public contract exists."""

    def publish_event(self, event: Mapping[str, Any]) -> None:
        """Publish a serialized event using application-owned transport."""


@dataclass(frozen=True, slots=True)
class CortexOpsEventSink:
    """Transport-agnostic CortexOps event boundary with no API assumptions."""

    transport: CortexOpsEventTransport
    capabilities: tuple[CapabilityDeclaration, ...]

    def __post_init__(self) -> None:
        if not self.capabilities:
            raise ValueError("a CortexOps sink must declare its capabilities")

    def emit(self, event: LifecycleEvent) -> None:
        self.transport.publish_event(lifecycle_event_to_dict(event))


@dataclass(frozen=True, slots=True)
class CompositeEventSink:
    sinks: tuple[EventSink, ...]

    @classmethod
    def from_iterable(cls, sinks: Iterable[EventSink]) -> CompositeEventSink:
        return cls(tuple(sinks))

    def emit(self, event: LifecycleEvent) -> None:
        for sink in self.sinks:
            sink.emit(event)


def lifecycle_event_to_dict(event: LifecycleEvent) -> dict[str, Any]:
    """Convert an event to transport-safe primitive values."""

    return {
        "event_type": event.event_type.value,
        "task_id": event.task_id,
        "correlation_id": event.correlation_id,
        "worker_id": event.worker_id,
        "occurred_at": event.occurred_at.isoformat(),
        "sequence": event.sequence,
        "state": event.state.value,
        "previous_state": (
            event.previous_state.value if event.previous_state is not None else None
        ),
        "name": event.name,
        "details": _to_primitive(event.details),
    }


def task_contract_telemetry(contract: TaskContract[Any, Any]) -> dict[str, Any]:
    """Return a content-free, stable description safe for lifecycle export."""

    codec = SafeJsonCodec()
    try:
        input_hash = _sha256(codec.dumps(contract.input))
    except (SerializationError, TypeError, ValueError):
        input_hash = None
    return {
        "schema_version": 1,
        "task_id": contract.task_id,
        "objective_hash": _sha256(contract.objective),
        "input_hash": input_hash,
        "acceptance_criteria": [
            {"name": item.name, "kind": type(item).__name__}
            for item in contract.acceptance_criteria
        ],
        "required_evidence": [
            {
                "evidence_type": item.evidence_type,
                "minimum_count": item.minimum_count,
                "minimum_trust_level": int(item.minimum_trust_level),
                "max_age_seconds": (
                    item.max_age.total_seconds() if item.max_age is not None else None
                ),
            }
            for item in contract.required_evidence
        ],
        "allowed_capabilities": sorted(contract.allowed_capabilities),
        "risk_level": contract.risk_level.value,
        "timeout_seconds": contract.timeout.total_seconds(),
        "idempotency_key_hash": _sha256(contract.idempotency_key),
        "metadata_keys": sorted(str(key) for key in contract.metadata),
    }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _to_primitive(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_to_primitive(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return _to_primitive(asdict(value))
    raise TypeError(f"event value {type(value).__name__} is not JSON serializable")
