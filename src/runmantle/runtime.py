"""Async, side-effect-free in-memory task execution runtime."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime
from typing import Any, TypeVar, cast

from ._validation import (
    require_non_empty,
    require_non_empty_attributes,
    require_unique,
)
from .contracts import TaskContract, TaskStatus
from .core import (
    CancellationToken,
    DependencyResolver,
    InMemoryDependencies,
    TaskCancelledError,
    TaskContext,
    TaskError,
    TaskErrorCode,
    TaskResult,
    TaskTimestamps,
    Worker,
    WorkerReport,
    WorkerReportedStatus,
)
from .evidence import (
    EvidenceCollection,
    EvidenceCollector,
    EvidenceItem,
    InMemoryEvidenceCollector,
    ObservableEvidenceCollector,
    _as_agent_claim,
    new_id,
    utc_now,
)
from .telemetry import (
    EventSink,
    LifecycleEvent,
    LifecycleEventType,
    NullEventSink,
    TaskEventEmitter,
    task_contract_telemetry,
)
from .verification import (
    VerificationResult,
    VerificationStatus,
    Verifier,
    enforce_verification_trust_boundary,
)

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")

EvidenceFactory = Callable[[], EvidenceCollector]
IdFactory = Callable[[], str]
Clock = Callable[[], datetime]


# States a task can only be entered once; entering one records ``finished_at``.
_TERMINAL_STATES: frozenset[TaskStatus] = frozenset(
    {
        TaskStatus.VERIFIED,
        TaskStatus.FAILED,
        TaskStatus.INCONCLUSIVE,
        TaskStatus.AWAITING_EVIDENCE,
        TaskStatus.AWAITING_APPROVAL,
        TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
    }
)

_ALLOWED_TRANSITIONS: Mapping[TaskStatus | None, frozenset[TaskStatus]] = {
    None: frozenset({TaskStatus.PENDING}),
    TaskStatus.PENDING: frozenset({TaskStatus.RUNNING, TaskStatus.FAILED}),
    TaskStatus.RUNNING: frozenset(
        {TaskStatus.AGENT_REPORTED_COMPLETE, TaskStatus.FAILED}
    ),
    TaskStatus.AGENT_REPORTED_COMPLETE: frozenset({TaskStatus.VERIFYING}),
    TaskStatus.VERIFYING: _TERMINAL_STATES,
    **{state: frozenset() for state in _TERMINAL_STATES},
}

_VERIFICATION_TO_TASK_STATUS: Mapping[VerificationStatus, TaskStatus] = {
    VerificationStatus.VERIFIED: TaskStatus.VERIFIED,
    VerificationStatus.FAILED: TaskStatus.FAILED,
    VerificationStatus.INCONCLUSIVE: TaskStatus.INCONCLUSIVE,
    VerificationStatus.AWAITING_EVIDENCE: TaskStatus.AWAITING_EVIDENCE,
    VerificationStatus.AWAITING_APPROVAL: TaskStatus.AWAITING_APPROVAL,
    VerificationStatus.AWAITING_RUNTIME_CONFIRMATION: (
        TaskStatus.AWAITING_RUNTIME_CONFIRMATION
    ),
}

# Errors attached to a conclusive-but-unsuccessful verification outcome.
_VERIFICATION_ERRORS: Mapping[TaskStatus, TaskError] = {
    TaskStatus.FAILED: TaskError(
        code=TaskErrorCode.VERIFICATION_FAILURE,
        message="reported output did not satisfy the acceptance criteria",
    ),
    TaskStatus.AWAITING_EVIDENCE: TaskError(
        code=TaskErrorCode.MISSING_EVIDENCE,
        message="required evidence has not been collected",
    ),
}


class _TaskTimedOut(Exception):
    pass


class _TaskWasCancelled(Exception):
    pass


class _Lifecycle:
    """Per-execution state machine and ordered event emitter."""

    def __init__(
        self,
        *,
        task_id: str,
        correlation_id: str,
        worker_id: str,
        sink: EventSink,
        clock: Clock,
    ) -> None:
        self.task_id = task_id
        self.correlation_id = correlation_id
        self.worker_id = worker_id
        self._sink = sink
        self._clock = clock
        self._sequence = 0
        self._emitted_evidence_ids: set[str] = set()
        self.status: TaskStatus | None = None
        self.pending_at: datetime | None = None
        self.started_at: datetime | None = None
        self.agent_reported_complete_at: datetime | None = None
        self.verification_started_at: datetime | None = None
        self.finished_at: datetime | None = None

    def transition(
        self,
        next_status: TaskStatus,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        allowed = _ALLOWED_TRANSITIONS[self.status]
        if next_status not in allowed:
            raise RuntimeError(
                f"invalid task transition from {self.status!s} to {next_status!s}"
            )

        previous = self.status
        occurred_at = self._clock()
        self.status = next_status
        self._sequence += 1
        if next_status is TaskStatus.PENDING:
            self.pending_at = occurred_at
        elif next_status is TaskStatus.RUNNING:
            self.started_at = occurred_at
        elif next_status is TaskStatus.AGENT_REPORTED_COMPLETE:
            self.agent_reported_complete_at = occurred_at
        elif next_status is TaskStatus.VERIFYING:
            self.verification_started_at = occurred_at
        elif next_status in _TERMINAL_STATES:
            self.finished_at = occurred_at

        self._sink.emit(
            LifecycleEvent(
                event_type=LifecycleEventType.STATE_TRANSITION,
                task_id=self.task_id,
                correlation_id=self.correlation_id,
                worker_id=self.worker_id,
                occurred_at=occurred_at,
                sequence=self._sequence,
                previous_state=previous,
                state=next_status,
                details=dict(details or {}),
            )
        )
        if next_status is TaskStatus.RUNNING:
            self.semantic(
                LifecycleEventType.TASK_STARTED,
                name="task.started",
                details=details,
            )
            self.semantic(
                LifecycleEventType.WORKER_STARTED,
                name="worker.started",
                details=details,
            )
        elif next_status is TaskStatus.AGENT_REPORTED_COMPLETE:
            self.semantic(
                LifecycleEventType.AGENT_REPORTED_COMPLETION,
                name="agent.reported_completion",
                details=details,
            )
        elif next_status is TaskStatus.FAILED:
            self.semantic(
                LifecycleEventType.TASK_FAILED,
                name="task.failed",
                details=details,
            )

    def semantic(
        self,
        event_type: LifecycleEventType,
        *,
        name: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if self.status is None:
            raise RuntimeError("task lifecycle has not started")
        self._sequence += 1
        self._sink.emit(
            LifecycleEvent(
                event_type=event_type,
                task_id=self.task_id,
                correlation_id=self.correlation_id,
                worker_id=self.worker_id,
                occurred_at=self._clock(),
                sequence=self._sequence,
                state=self.status,
                name=name,
                details=dict(details or {}),
            )
        )

    def evidence_collected(self, item: EvidenceItem) -> None:
        if item.evidence_id in self._emitted_evidence_ids:
            return
        self._emitted_evidence_ids.add(item.evidence_id)
        self.semantic(
            LifecycleEventType.EVIDENCE_COLLECTED,
            name="evidence.collected",
            details={
                "evidence_id": item.evidence_id,
                "evidence_type": item.type,
                "source": item.source,
                "artifact_reference": item.artifact_reference,
                "checksum": item.checksum,
                "acquisition_method": item.acquisition_method,
                "trust_level": int(item.trust_level),
                "effective_trust_level": int(item.effective_trust_level),
                "trust_established": item.trust_established,
                "trust_origin": item.trust_origin,
                "origin_hash": item.origin_hash,
                "expires_at": item.expires_at,
                "provenance": item.provenance,
            },
        )

    def worker_event(
        self,
        name: str,
        details: Mapping[str, Any] | None,
        event_type: LifecycleEventType,
    ) -> None:
        if not name.strip():
            raise ValueError("worker event name must not be empty")
        if self.status is None:
            raise RuntimeError("task lifecycle has not started")
        if event_type not in {
            LifecycleEventType.TASK_PROGRESS,
            LifecycleEventType.TOOL_ACTION_REQUESTED,
            LifecycleEventType.WORKER_EVENT,
        }:
            raise ValueError("workers may emit only progress or tool/action events")
        self.semantic(event_type, name=name, details=details)

    def timestamps(self) -> TaskTimestamps:
        if self.pending_at is None:
            raise RuntimeError("pending timestamp was not recorded")
        return TaskTimestamps(
            pending_at=self.pending_at,
            started_at=self.started_at,
            agent_reported_complete_at=self.agent_reported_complete_at,
            verification_started_at=self.verification_started_at,
            finished_at=self.finished_at or self._clock(),
        )


class _BoundTaskEventEmitter(TaskEventEmitter):
    def __init__(self, lifecycle: _Lifecycle) -> None:
        self._lifecycle = lifecycle

    def emit(
        self,
        name: str,
        details: Mapping[str, Any] | None = None,
        *,
        event_type: LifecycleEventType = LifecycleEventType.TASK_PROGRESS,
    ) -> None:
        self._lifecycle.worker_event(name, details, event_type)


class InMemoryRuntime:
    """Execute one async worker locally and retain no external runtime state."""

    def __init__(
        self,
        *,
        verifier: Verifier | None = None,
        evidence_factory: EvidenceFactory | None = None,
        event_sink: EventSink | None = None,
        dependencies: DependencyResolver | None = None,
        clock: Clock = utc_now,
        id_factory: IdFactory | None = None,
    ) -> None:
        self._verifier = verifier
        self._evidence_factory = evidence_factory or InMemoryEvidenceCollector
        self._event_sink = event_sink or NullEventSink()
        self._dependencies = dependencies or InMemoryDependencies()
        self._clock = clock
        self._id_factory = id_factory or new_id

    async def execute(
        self,
        worker: Worker[InputT, OutcomeT],
        contract: TaskContract[InputT, OutcomeT],
        *,
        cancellation: CancellationToken | None = None,
        correlation_id: str | None = None,
    ) -> TaskResult[OutcomeT]:
        self._validate_worker(worker)
        resolved_correlation_id = correlation_id or self._id_factory()
        require_non_empty(resolved_correlation_id, "correlation_id")

        lifecycle = _Lifecycle(
            task_id=contract.task_id,
            correlation_id=resolved_correlation_id,
            worker_id=worker.id,
            sink=self._event_sink,
            clock=self._clock,
        )
        lifecycle.transition(
            TaskStatus.PENDING,
            {
                "task_contract": task_contract_telemetry(contract),
                "risk_level": contract.risk_level,
            },
        )
        token = cancellation or CancellationToken()
        evidence_collector = self._evidence_factory()
        if isinstance(evidence_collector, ObservableEvidenceCollector):
            evidence_collector.add_listener(lifecycle.evidence_collected)

        if token.is_cancelled:
            return self._failed(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence_collector.snapshot(),
                reason="cancelled",
                errors=(self._cancellation_error(),),
            )

        context = TaskContext(
            correlation_id=resolved_correlation_id,
            task_metadata=dict(contract.metadata),
            cancellation=token,
            event_emitter=_BoundTaskEventEmitter(lifecycle),
            dependencies=self._dependencies,
            evidence=evidence_collector,
            allowed_capabilities=contract.allowed_capabilities.intersection(
                item.name for item in worker.capabilities
            ),
        )
        lifecycle.transition(
            TaskStatus.RUNNING,
            {
                "worker_name": worker.name,
                "worker_role": worker.role,
                "worker_version": worker.version,
                "declared_capabilities": [item.name for item in worker.capabilities],
            },
        )

        try:
            report = await self._execute_with_guards(worker, contract, context)
        except _TaskTimedOut:
            return self._failed(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence_collector.snapshot(),
                reason="timeout",
                errors=(
                    TaskError(
                        code=TaskErrorCode.TIMEOUT,
                        message=f"task exceeded timeout of {contract.timeout}",
                    ),
                ),
            )
        except (_TaskWasCancelled, TaskCancelledError) as error:
            return self._failed(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence_collector.snapshot(),
                reason="cancelled",
                errors=(self._cancellation_error(str(error)),),
            )
        except Exception as error:  # noqa: BLE001 - worker failures become task errors
            return self._failed(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence_collector.snapshot(),
                reason="worker_failure",
                errors=(
                    TaskError(
                        code=TaskErrorCode.WORKER_FAILURE,
                        message=str(error),
                        error_type=type(error).__name__,
                    ),
                ),
                details={"error_type": type(error).__name__},
            )

        reported_evidence = EvidenceCollection(
            tuple(_as_agent_claim(item) for item in report.evidence)
        )
        evidence = evidence_collector.snapshot() + reported_evidence
        for item in reported_evidence:
            lifecycle.evidence_collected(item)
        if report.status is WorkerReportedStatus.FAILED:
            return self._failed(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence,
                reason="worker_reported_failure",
                errors=report.errors
                or (
                    TaskError(
                        code=TaskErrorCode.WORKER_REPORTED_FAILURE,
                        message="worker reported failure without an error",
                    ),
                ),
                reported_status=report.status,
            )

        lifecycle.semantic(
            LifecycleEventType.WORKER_COMPLETED,
            name="worker.completed",
            details={"reported_status": report.status},
        )
        lifecycle.transition(TaskStatus.AGENT_REPORTED_COMPLETE)
        if self._verifier is None:
            return self._result(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence,
                reported_status=report.status,
                output=report.output,
                errors=report.errors,
            )
        return self._verify(
            self._verifier,
            contract=contract,
            lifecycle=lifecycle,
            evidence=evidence,
            report=report,
        )

    def _verify(
        self,
        verifier: Verifier,
        *,
        contract: TaskContract[Any, OutcomeT],
        lifecycle: _Lifecycle,
        evidence: EvidenceCollection,
        report: WorkerReport[OutcomeT],
    ) -> TaskResult[OutcomeT]:
        """Verify a reported outcome and map the verdict to a terminal state."""

        lifecycle.transition(TaskStatus.VERIFYING)
        try:
            verification = verifier.verify(
                contract,
                cast(OutcomeT, report.output),
                evidence,
            )
            verification = enforce_verification_trust_boundary(
                contract,
                evidence,
                verification,
                decision_time=self._clock(),
            )
        except Exception as error:  # noqa: BLE001 - verifier failures are inconclusive
            lifecycle.semantic(
                LifecycleEventType.VERIFICATION_RESULT,
                name="verification.result",
                details={
                    "status": VerificationStatus.INCONCLUSIVE,
                    "error_type": type(error).__name__,
                },
            )
            lifecycle.transition(
                TaskStatus.INCONCLUSIVE,
                {"reason": "verifier_failure", "error_type": type(error).__name__},
            )
            return self._result(
                contract=contract,
                lifecycle=lifecycle,
                evidence=evidence,
                reported_status=report.status,
                output=report.output,
                errors=(
                    *report.errors,
                    TaskError(
                        code=TaskErrorCode.VERIFICATION_FAILURE,
                        message=str(error),
                        error_type=type(error).__name__,
                    ),
                ),
            )

        final_status = _VERIFICATION_TO_TASK_STATUS[verification.status]
        lifecycle.semantic(
            LifecycleEventType.VERIFICATION_RESULT,
            name="verification.result",
            details={
                "status": verification.status,
                "missing_evidence": verification.missing_evidence,
                "contradictory_evidence": verification.contradictory_evidence,
                "criteria": [
                    {
                        "name": item.name,
                        "passed": item.passed,
                        "conclusive": item.conclusive,
                        "awaiting_approval": item.awaiting_approval,
                        "awaiting_runtime_confirmation": (
                            item.awaiting_runtime_confirmation
                        ),
                    }
                    for item in verification.criteria
                ],
            },
        )
        lifecycle.transition(
            final_status,
            {"verification_status": verification.status},
        )
        verification_error = _VERIFICATION_ERRORS.get(final_status)
        verification_errors: tuple[TaskError, ...] = (
            () if verification_error is None else (verification_error,)
        )
        return self._result(
            contract=contract,
            lifecycle=lifecycle,
            evidence=evidence,
            reported_status=report.status,
            output=report.output,
            errors=report.errors + verification_errors,
            verification=verification,
        )

    def _failed(
        self,
        *,
        contract: TaskContract[Any, OutcomeT],
        lifecycle: _Lifecycle,
        evidence: EvidenceCollection,
        reason: str,
        errors: tuple[TaskError, ...],
        reported_status: WorkerReportedStatus | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> TaskResult[OutcomeT]:
        """Record one terminal failure transition and build its task result."""

        if lifecycle.status is TaskStatus.RUNNING:
            lifecycle.semantic(
                LifecycleEventType.WORKER_FAILED,
                name="worker.failed",
                details={"reason": reason, **(details or {})},
            )
        lifecycle.transition(TaskStatus.FAILED, {"reason": reason, **(details or {})})
        return self._result(
            contract=contract,
            lifecycle=lifecycle,
            evidence=evidence,
            reported_status=reported_status,
            errors=errors,
        )

    async def _execute_with_guards(
        self,
        worker: Worker[InputT, OutcomeT],
        contract: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        worker_task = asyncio.create_task(worker.execute(contract, context))
        cancellation_waiter = asyncio.create_task(context.cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {worker_task, cancellation_waiter},
                timeout=contract.timeout.total_seconds(),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if worker_task in done:
                try:
                    return await worker_task
                except asyncio.CancelledError as error:
                    raise _TaskWasCancelled("worker execution was cancelled") from error
            if cancellation_waiter in done:
                worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await worker_task
                raise _TaskWasCancelled("task cancellation was requested")

            worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await worker_task
            raise _TaskTimedOut
        finally:
            if not worker_task.done():
                worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await worker_task
            if not cancellation_waiter.done():
                cancellation_waiter.cancel()
                with suppress(asyncio.CancelledError):
                    await cancellation_waiter

    @staticmethod
    def _validate_worker(worker: Worker[Any, Any]) -> None:
        require_non_empty_attributes(
            worker,
            ("id", "name", "role", "version"),
            prefix="worker",
        )
        if not worker.capabilities:
            raise ValueError("a worker must declare at least one capability")
        require_unique(
            (item.name for item in worker.capabilities),
            "worker capability names must be unique",
        )

    @staticmethod
    def _cancellation_error(
        message: str = "task cancellation was requested",
    ) -> TaskError:
        return TaskError(code=TaskErrorCode.CANCELLED, message=message)

    @staticmethod
    def _result(
        *,
        contract: TaskContract[Any, OutcomeT],
        lifecycle: _Lifecycle,
        evidence: EvidenceCollection,
        reported_status: WorkerReportedStatus | None = None,
        output: OutcomeT | None = None,
        errors: tuple[TaskError, ...] = (),
        verification: VerificationResult | None = None,
    ) -> TaskResult[OutcomeT]:
        if lifecycle.status is None:
            raise RuntimeError("task lifecycle has no status")
        for item in evidence:
            lifecycle.evidence_collected(item)
        return TaskResult(
            task_id=contract.task_id,
            correlation_id=lifecycle.correlation_id,
            status=lifecycle.status,
            reported_status=reported_status,
            output=output,
            evidence=evidence,
            errors=errors,
            timestamps=lifecycle.timestamps(),
            final_verification_result=verification,
        )


# Compatibility aliases for the initial package naming.
WorkerRuntime = InMemoryRuntime
RunResult = TaskResult
RunStatus = TaskStatus
ErrorInfo = TaskError
