"""Provider-neutral worker, context, cancellation, and result models."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Generic, Protocol, TypeVar, cast

from ._validation import require_non_empty
from .capabilities import Capability as Capability
from .capabilities import CapabilityDeclaration
from .contracts import TaskContract, TaskStatus
from .evidence import EvidenceCollection, EvidenceCollector
from .telemetry import TaskEventEmitter
from .verification import VerificationResult

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")
DependencyT = TypeVar("DependencyT")


class TaskCancelledError(Exception):
    """Raised by cooperative workers when their task is cancelled."""


@dataclass(slots=True)
class CancellationToken:
    """Cooperative cancellation signal that can also be awaited by the runtime."""

    _event: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        """Alias that reads naturally in worker control flow."""

        return self.is_cancelled

    def cancel(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise TaskCancelledError("task cancellation was requested")


@dataclass(frozen=True, slots=True)
class DependencyKey(Generic[DependencyT]):
    """Typed key used to resolve an injected runtime dependency."""

    name: str
    expected_type: type[DependencyT]

    def __post_init__(self) -> None:
        require_non_empty(self.name, "dependency key name")


class DependencyResolver(Protocol):
    def resolve(self, key: DependencyKey[DependencyT]) -> DependencyT:
        """Resolve a dependency or raise LookupError."""


class CheckpointWriter(Protocol):
    """Explicit durable checkpoint boundary exposed to a running worker."""

    def save(
        self,
        payload: Mapping[str, Any],
        *,
        label: str | None = None,
        checkpoint_id: str | None = None,
    ) -> str:
        """Persist application state and return its stable checkpoint ID."""


class NullCheckpointWriter:
    """Non-durable checkpoint boundary used by ``InMemoryRuntime``."""

    def save(
        self,
        payload: Mapping[str, Any],
        *,
        label: str | None = None,
        checkpoint_id: str | None = None,
    ) -> str:
        del payload, label, checkpoint_id
        raise RuntimeError("the active runtime does not provide durable checkpoints")


@dataclass(slots=True)
class InMemoryDependencies:
    """Small type-checking dependency container owned by the application."""

    _values: dict[DependencyKey[Any], object] = field(default_factory=dict)

    def register(
        self,
        key: DependencyKey[DependencyT],
        value: DependencyT,
    ) -> None:
        if not isinstance(value, key.expected_type):
            raise TypeError(
                f"dependency {key.name!r} must be {key.expected_type.__name__}"
            )
        self._values[key] = value

    def resolve(self, key: DependencyKey[DependencyT]) -> DependencyT:
        try:
            value = self._values[key]
        except KeyError as error:
            raise LookupError(f"dependency {key.name!r} is not registered") from error
        return cast(DependencyT, value)


@dataclass(frozen=True, slots=True)
class TaskContext:
    """Runtime dependencies and controls available during one task."""

    correlation_id: str
    task_metadata: Mapping[str, Any]
    cancellation: CancellationToken
    event_emitter: TaskEventEmitter
    dependencies: DependencyResolver
    evidence: EvidenceCollector
    allowed_capabilities: frozenset[str]
    checkpoints: CheckpointWriter = field(default_factory=NullCheckpointWriter)

    def require_capability(self, capability: str) -> None:
        """Fail locally if a worker attempts a capability the contract disallows."""

        if capability not in self.allowed_capabilities:
            raise PermissionError(
                f"capability {capability!r} is not allowed for this task"
            )

    def save_checkpoint(
        self,
        payload: Mapping[str, Any],
        *,
        label: str | None = None,
        checkpoint_id: str | None = None,
    ) -> str:
        """Persist one explicit application-level resume boundary."""

        self.require_capability("checkpoint")
        return self.checkpoints.save(
            payload,
            label=label,
            checkpoint_id=checkpoint_id,
        )


# Compatibility alias for the earlier public name.
WorkerContext = TaskContext


class WorkerReportedStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"


class TaskErrorCode(StrEnum):
    WORKER_FAILURE = "worker_failure"
    WORKER_REPORTED_FAILURE = "worker_reported_failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    MISSING_EVIDENCE = "missing_evidence"
    VERIFICATION_FAILURE = "verification_failure"


@dataclass(frozen=True, slots=True)
class TaskError:
    code: TaskErrorCode
    message: str
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class WorkerReport(Generic[OutcomeT]):
    """What a worker reports; this is never itself proof of success."""

    status: WorkerReportedStatus
    output: OutcomeT | None = None
    evidence: EvidenceCollection = field(default_factory=EvidenceCollection)
    errors: tuple[TaskError, ...] = ()

    @classmethod
    def completed(
        cls,
        output: OutcomeT,
        *,
        evidence: EvidenceCollection | None = None,
    ) -> WorkerReport[OutcomeT]:
        return cls(
            status=WorkerReportedStatus.COMPLETED,
            output=output,
            evidence=evidence or EvidenceCollection(),
        )

    @classmethod
    def failed(
        cls,
        *errors: TaskError,
        evidence: EvidenceCollection | None = None,
    ) -> WorkerReport[Any]:
        return cls(
            status=WorkerReportedStatus.FAILED,
            evidence=evidence or EvidenceCollection(),
            errors=tuple(errors),
        )


@dataclass(frozen=True, slots=True)
class TaskTimestamps:
    pending_at: datetime
    started_at: datetime | None = None
    agent_reported_complete_at: datetime | None = None
    verification_started_at: datetime | None = None
    finished_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class TaskResult(Generic[OutcomeT]):
    """Complete runtime result with reported and verified status separated."""

    task_id: str
    correlation_id: str
    status: TaskStatus
    reported_status: WorkerReportedStatus | None
    output: OutcomeT | None
    evidence: EvidenceCollection
    errors: tuple[TaskError, ...]
    timestamps: TaskTimestamps
    final_verification_result: VerificationResult | None

    @property
    def succeeded(self) -> bool:
        """True only for a verified result, never for a worker report alone."""

        return self.status is TaskStatus.VERIFIED


class Worker(Protocol[InputT, OutcomeT]):
    """Strongly typed asynchronous worker contract."""

    @property
    def id(self) -> str:
        """Stable worker identifier."""

    @property
    def name(self) -> str:
        """Human-readable worker name."""

    @property
    def role(self) -> str:
        """Worker responsibility within the application."""

    @property
    def version(self) -> str:
        """Worker implementation version."""

    @property
    def capabilities(self) -> tuple[CapabilityDeclaration, ...]:
        """Capabilities this worker may use when a task permits them."""

    async def execute(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        """Execute a task and report an outcome without claiming verification."""
