"""Restart-safe local task runtime built on the durable persistence boundary."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

from ._validation import require_non_empty, require_non_empty_attributes, require_unique
from .approvals import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRevocation,
    StoredApproval,
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
    Worker,
    WorkerReport,
    WorkerReportedStatus,
)
from .evidence import (
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceCollector,
    EvidenceItem,
    EvidenceTrustLevel,
    _as_agent_claim,
    new_id,
    utc_now,
)
from .persistence import (
    CheckpointRecord,
    PersistenceStore,
    SQLiteStore,
    StoredTask,
)
from .recovery import RuntimeConfirmation
from .serialization import SerializationError
from .telemetry import (
    EventSink,
    LifecycleEvent,
    LifecycleEventType,
    NullEventSink,
    TaskEventEmitter,
)
from .verification import (
    RuleBasedVerifier,
    VerificationResult,
    VerificationStatus,
    Verifier,
    enforce_verification_trust_boundary,
)

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]

logger = logging.getLogger(__name__)


class ResumeNotPossibleError(RuntimeError):
    """Raised when a task has no safe explicit resume boundary."""


class CheckpointedWorker(Protocol[InputT, OutcomeT]):
    """Optional worker extension for application-level checkpoint resumption."""

    async def resume(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
        checkpoint: CheckpointRecord,
    ) -> WorkerReport[OutcomeT]:
        """Continue from an explicit checkpoint; never from a Python frame."""


class _TaskTimedOut(Exception):
    pass


class _TaskWasCancelled(Exception):
    pass


class DurableRuntime:
    """Transactional local runtime with restart-safe lifecycle continuation."""

    def __init__(
        self,
        *,
        store: PersistenceStore | None = None,
        database_path: str | Path = Path("./runmantle.db"),
        verifier: Verifier | None = None,
        event_sink: EventSink | None = None,
        dependencies: DependencyResolver | None = None,
        clock: Clock = utc_now,
        id_factory: IdFactory = new_id,
    ) -> None:
        self.store: PersistenceStore = store or SQLiteStore(database_path)
        self._verifier = verifier
        self._event_sink = event_sink or NullEventSink()
        self._dependencies = dependencies or InMemoryDependencies()
        self._clock = clock
        self._id_factory = id_factory

    def start(
        self,
        worker: Worker[InputT, OutcomeT],
        contract: TaskContract[InputT, OutcomeT],
        *,
        correlation_id: str | None = None,
    ) -> StoredTask:
        """Persist a PENDING task without invoking worker code."""

        self._validate_worker(worker)
        resolved_correlation_id = correlation_id or self._id_factory()
        require_non_empty(resolved_correlation_id, "correlation_id")
        task, event = self.store.create_task(
            contract,
            correlation_id=resolved_correlation_id,
            worker_id=worker.id,
            occurred_at=self._clock(),
        )
        self._publish(event)
        return task

    async def execute(
        self,
        worker: Worker[InputT, OutcomeT],
        contract: TaskContract[InputT, OutcomeT],
        *,
        cancellation: CancellationToken | None = None,
        correlation_id: str | None = None,
    ) -> TaskResult[OutcomeT]:
        """Create and run one durable task through its current verification gate."""

        self.start(worker, contract, correlation_id=correlation_id)
        return cast(
            TaskResult[OutcomeT],
            await self.resume(
                contract.task_id,
                worker=worker,
                contract=contract,
                cancellation=cancellation,
            ),
        )

    def load(self, task_id: str) -> StoredTask:
        """Load the current task snapshot without requiring application code."""

        return self.store.load_task(task_id)

    load_task = load

    def event_history(self, task_id: str) -> tuple[LifecycleEvent, ...]:
        """Return the complete, transactionally ordered event history."""

        return self.store.event_history(task_id)

    def add_evidence(self, task_id: str, item: EvidenceItem) -> EvidenceItem:
        """Add caller evidence as a claim; trusted providers use mediated boundaries."""

        stored, event = self.store.record_evidence(task_id, _as_agent_claim(item))
        if event is not None:
            self._publish(event)
        return stored

    def request_approval(
        self,
        task_id: str,
        *,
        approval_key: str,
        reason: str,
        approval_id: str | None = None,
    ) -> str:
        """Persist a pending approval request for a durable verification gate."""

        resolved_id = approval_id or self._id_factory()
        _, event = self.store.request_approval(
            task_id,
            approval_id=resolved_id,
            approval_key=approval_key,
            reason=reason,
            occurred_at=self._clock(),
        )
        if event is not None:
            self._publish(event)
        return resolved_id

    def create_approval_request(self, request: ApprovalRequest) -> StoredApproval:
        """Persist an exact-hash approval request for later authenticated decision."""

        stored, event = self.store.create_approval_request(request)
        if event is not None:
            self._publish(event)
        return stored

    def record_approval_decision(
        self,
        decision: ApprovalDecision,
    ) -> StoredApproval:
        """Persist a decision whose approver assertion came from the application."""

        stored, event = self.store.record_approval_decision(decision)
        if event is not None:
            self._publish(event)
        return stored

    def revoke_approval(self, revocation: ApprovalRevocation) -> StoredApproval:
        """Revoke an unconsumed approval grant."""

        stored, event = self.store.revoke_approval(revocation)
        if event is not None:
            self._publish(event)
        return stored

    def load_approval(self, approval_id: str) -> StoredApproval:
        """Load the complete durable approval request/decision/use snapshot."""

        return self.store.load_approval(approval_id)

    def decide_approval(
        self,
        task_id: str,
        *,
        approval_key: str,
        approved: bool,
        approved_by: str,
        reason: str,
        approval_id: str | None = None,
    ) -> str:
        """Persist one exact approval decision for later resume."""

        resolved_id = approval_id or self._id_factory()
        _, event = self.store.decide_approval(
            task_id,
            approval_key=approval_key,
            approved=approved,
            approved_by=approved_by,
            reason=reason,
            occurred_at=self._clock(),
            approval_id=resolved_id,
        )
        if event is not None:
            self._publish(event)
        return resolved_id

    def add_runtime_confirmation(
        self,
        task_id: str,
        confirmation: RuntimeConfirmation,
    ) -> RuntimeConfirmation:
        """Persist an action-bound runtime confirmation for later verification."""

        event = self.store.save_runtime_confirmation(task_id, confirmation)
        if event is not None:
            self._publish(event)
        return confirmation

    async def resume(
        self,
        task_id: str,
        *,
        worker: Worker[Any, Any] | None = None,
        contract: TaskContract[Any, Any] | None = None,
        verifier: Verifier | None = None,
        cancellation: CancellationToken | None = None,
    ) -> TaskResult[Any]:
        """Continue only from a persisted lifecycle or explicit checkpoint boundary."""

        stored = self.store.load_task(task_id)
        if stored.status in {TaskStatus.VERIFIED, TaskStatus.FAILED}:
            return self._result(stored)
        if contract is None:
            raise ResumeNotPossibleError(
                "resume requires the executable TaskContract; persisted snapshots "
                "never deserialize application callables"
            )
        self.store.validate_contract(task_id, contract)

        if stored.status is TaskStatus.PENDING:
            if worker is None:
                raise ResumeNotPossibleError("a PENDING task requires its worker")
            stored = await self._run_worker(
                worker,
                contract,
                stored,
                cancellation=cancellation,
            )
        elif stored.status is TaskStatus.RUNNING:
            if worker is None:
                raise ResumeNotPossibleError(
                    "a RUNNING task requires a checkpoint-capable worker"
                )
            checkpoint = self.store.latest_checkpoint(task_id)
            resume_method = getattr(worker, "resume", None)
            if checkpoint is None or not callable(resume_method):
                raise ResumeNotPossibleError(
                    "RUNNING task cannot resume: no explicit checkpoint and "
                    "CheckpointedWorker.resume implementation are both available"
                )
            event = self.store.claim_checkpoint_resume(
                task_id,
                checkpoint_id=checkpoint.checkpoint_id,
                expected_version=stored.version,
                occurred_at=self._clock(),
            )
            self._publish(event)
            stored = self.store.load_task(task_id)
            stored = await self._run_worker(
                worker,
                contract,
                stored,
                cancellation=cancellation,
                checkpoint=checkpoint,
            )

        resolved_verifier = verifier or self._verifier
        if (
            stored.status is TaskStatus.AGENT_REPORTED_COMPLETE
            and resolved_verifier is None
        ):
            return self._result(stored)
        if stored.status in {
            TaskStatus.AGENT_REPORTED_COMPLETE,
            TaskStatus.VERIFYING,
            TaskStatus.AWAITING_EVIDENCE,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
            TaskStatus.INCONCLUSIVE,
        }:
            if resolved_verifier is None:
                raise ResumeNotPossibleError(
                    "verification continuation requires a verifier"
                )
            stored = self._continue_verification(contract, stored, resolved_verifier)
        return self._result(stored)

    def verify_after_recovery(
        self,
        task_id: str,
        *,
        plan_id: str,
        contract: TaskContract[Any, Any],
        verifier: Verifier | None = None,
    ) -> TaskResult[Any]:
        """Re-run outcome verification from a satisfied recovery boundary.

        This is the only recovery path that may move an original failed task back
        to ``VERIFYING``. The recovery executor must first persist independently
        acquired postcondition evidence and the ``postconditions_satisfied`` state.
        """

        recovery = self.store.load_recovery_state(plan_id)
        if recovery is None or recovery.task_id != task_id:
            raise ResumeNotPossibleError("durable recovery plan does not exist")
        if recovery.status != "postconditions_satisfied":
            raise ResumeNotPossibleError(
                "recovery outcome verification requires satisfied postconditions"
            )
        self.store.validate_contract(task_id, contract)
        resolved_verifier = verifier or self._verifier
        if resolved_verifier is None:
            raise ResumeNotPossibleError("recovery verification requires a verifier")
        stored = self.store.load_task(task_id)
        if stored.status not in {
            TaskStatus.FAILED,
            TaskStatus.INCONCLUSIVE,
            TaskStatus.AWAITING_EVIDENCE,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
        }:
            raise ResumeNotPossibleError(
                f"task state {stored.status.value} is not a recovery boundary"
            )
        stored, event = self.store.transition(
            task_id,
            expected_version=stored.version,
            next_status=TaskStatus.VERIFYING,
            occurred_at=self._clock(),
            details={"recovery_plan_id": plan_id, "recovery_verified": False},
            dedupe_key=f"recovery:{plan_id}:verification-started",
        )
        self._publish(event)
        verified = self._continue_verification(contract, stored, resolved_verifier)
        return self._result(verified)

    async def _run_worker(
        self,
        worker: Worker[Any, Any],
        contract: TaskContract[Any, Any],
        stored: StoredTask,
        *,
        cancellation: CancellationToken | None,
        checkpoint: CheckpointRecord | None = None,
    ) -> StoredTask:
        self._validate_worker(worker)
        if checkpoint is None:
            stored, transition = self.store.transition(
                stored.task_id,
                expected_version=stored.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=self._clock(),
                details={
                    "worker_name": worker.name,
                    "worker_role": worker.role,
                    "worker_version": worker.version,
                    "declared_capabilities": [
                        item.name for item in worker.capabilities
                    ],
                },
                dedupe_key="execution-started",
            )
            self._publish(transition)
            self._publish(
                self.store.append_event(
                    stored.task_id,
                    event_type=LifecycleEventType.TASK_STARTED,
                    occurred_at=self._clock(),
                    name="task.started",
                    dedupe_key="task-started",
                )
            )
            self._publish(
                self.store.append_event(
                    stored.task_id,
                    event_type=LifecycleEventType.WORKER_STARTED,
                    occurred_at=self._clock(),
                    name="worker.started",
                    dedupe_key="worker-started",
                )
            )

        token = cancellation or CancellationToken()
        context = TaskContext(
            correlation_id=stored.correlation_id,
            task_metadata=dict(contract.metadata),
            cancellation=token,
            event_emitter=_DurableEventEmitter(self, stored.task_id),
            dependencies=self._dependencies,
            evidence=_DurableEvidenceCollector(self, stored.task_id),
            allowed_capabilities=contract.allowed_capabilities.intersection(
                item.name for item in worker.capabilities
            ),
            checkpoints=_DurableCheckpointWriter(self, stored.task_id),
        )
        operation: Awaitable[WorkerReport[Any]]
        try:
            if checkpoint is None:
                operation = worker.execute(contract, context)
            else:
                resume_method = cast(
                    CheckpointedWorker[Any, Any],
                    worker,
                ).resume
                operation = resume_method(contract, context, checkpoint)
            report = await self._execute_with_guards(
                operation,
                timeout_seconds=contract.timeout.total_seconds(),
                cancellation=token,
            )
        except _TaskTimedOut:
            return self._record_runtime_failure(
                stored.task_id,
                TaskError(
                    code=TaskErrorCode.TIMEOUT,
                    message=f"task exceeded timeout of {contract.timeout}",
                ),
                reason="timeout",
            )
        except (_TaskWasCancelled, TaskCancelledError) as error:
            return self._record_runtime_failure(
                stored.task_id,
                TaskError(code=TaskErrorCode.CANCELLED, message=str(error)),
                reason="cancelled",
            )
        except Exception as error:  # noqa: BLE001 - durable structured failure
            return self._record_runtime_failure(
                stored.task_id,
                TaskError(
                    code=TaskErrorCode.WORKER_FAILURE,
                    message=str(error),
                    error_type=type(error).__name__,
                ),
                reason="worker_failure",
            )

        try:
            for item in report.evidence:
                self.add_evidence(stored.task_id, item)
            current = self.store.load_task(stored.task_id)
            errors = report.errors
            if report.status is WorkerReportedStatus.FAILED and not errors:
                errors = (
                    TaskError(
                        code=TaskErrorCode.WORKER_REPORTED_FAILURE,
                        message="worker reported failure without an error",
                    ),
                )
            result, events = self.store.record_worker_report(
                stored.task_id,
                expected_version=current.version,
                reported_status=report.status,
                output=report.output,
                errors=errors,
                occurred_at=self._clock(),
            )
        except SerializationError as error:
            return self._record_runtime_failure(
                stored.task_id,
                TaskError(
                    code=TaskErrorCode.WORKER_FAILURE,
                    message=str(error),
                    error_type=type(error).__name__,
                ),
                reason="unsafe_persisted_value",
            )
        for event in events:
            self._publish(event)
        return result

    def _continue_verification(
        self,
        contract: TaskContract[Any, Any],
        stored: StoredTask,
        verifier: Verifier,
    ) -> StoredTask:
        if stored.status in {
            TaskStatus.AWAITING_EVIDENCE,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
        }:
            token = self.store.continuation_token(stored.task_id, stored.status)
            if token == stored.wait_token:
                return stored

        if stored.status is not TaskStatus.VERIFYING:
            stored, event = self.store.transition(
                stored.task_id,
                expected_version=stored.version,
                next_status=TaskStatus.VERIFYING,
                occurred_at=self._clock(),
                details={
                    "resumed": stored.status is not TaskStatus.AGENT_REPORTED_COMPLETE
                },
                dedupe_key=f"verification-start:{stored.version}",
            )
            self._publish(event)

        effective = self._effective_verifier(stored.task_id, verifier)
        evidence = self.store.evidence(stored.task_id)
        try:
            verification = effective.verify(contract, stored.output, evidence)
            verification = enforce_verification_trust_boundary(
                contract,
                evidence,
                verification,
                decision_time=self._clock(),
            )
        except Exception as error:  # noqa: BLE001 - verifier failures are persisted
            verification = VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message=f"verifier raised {type(error).__name__}: {error}",
            )

        final_status = _VERIFICATION_TO_TASK_STATUS[verification.status]
        wait_token = (
            self.store.continuation_token(stored.task_id, final_status)
            if final_status
            in {
                TaskStatus.AWAITING_EVIDENCE,
                TaskStatus.AWAITING_APPROVAL,
                TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
            }
            else None
        )
        errors = tuple(
            item
            for item in stored.errors
            if item.code
            not in {TaskErrorCode.MISSING_EVIDENCE, TaskErrorCode.VERIFICATION_FAILURE}
        )
        if final_status is TaskStatus.FAILED:
            errors += (
                TaskError(
                    code=TaskErrorCode.VERIFICATION_FAILURE,
                    message="reported output did not satisfy acceptance criteria",
                ),
            )
        elif final_status is TaskStatus.AWAITING_EVIDENCE:
            errors += (
                TaskError(
                    code=TaskErrorCode.MISSING_EVIDENCE,
                    message="required evidence has not been collected",
                ),
            )
        stored, events = self.store.record_verification(
            stored.task_id,
            expected_version=stored.version,
            result=verification,
            final_status=final_status,
            errors=errors,
            occurred_at=self._clock(),
            wait_token=wait_token,
        )
        for event in events:
            self._publish(event)
        return stored

    def _effective_verifier(self, task_id: str, verifier: Verifier) -> Verifier:
        if not isinstance(verifier, RuleBasedVerifier):
            return verifier
        return RuleBasedVerifier(
            runtime_confirmations={
                **verifier.runtime_confirmations,
                **self.store.runtime_confirmation_values(task_id),
            },
            approvals={
                **verifier.approvals,
                **self.store.approval_values(
                    task_id,
                    occurred_at=self._clock(),
                ),
            },
            clock=verifier.clock,
        )

    def _record_runtime_failure(
        self,
        task_id: str,
        error: TaskError,
        *,
        reason: str,
    ) -> StoredTask:
        current = self.store.load_task(task_id)
        stored, events = self.store.record_runtime_failure(
            task_id,
            expected_version=current.version,
            errors=(error,),
            occurred_at=self._clock(),
            reason=reason,
        )
        for event in events:
            self._publish(event)
        return stored

    async def _execute_with_guards(
        self,
        operation: Awaitable[WorkerReport[Any]],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> WorkerReport[Any]:
        worker_task: asyncio.Future[WorkerReport[Any]] = asyncio.ensure_future(
            operation
        )
        cancellation_waiter = asyncio.create_task(cancellation.wait())
        waiters: set[asyncio.Future[Any]] = {worker_task, cancellation_waiter}
        try:
            done, _ = await asyncio.wait(
                waiters,
                timeout=timeout_seconds,
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

    def _result(self, stored: StoredTask) -> TaskResult[Any]:
        return stored.to_result(self.store.evidence(stored.task_id))

    def _publish(self, event: LifecycleEvent) -> None:
        try:
            self._event_sink.emit(event)
        except Exception:
            logger.warning(
                "external event sink failed after durable event commit",
                exc_info=True,
            )

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


class _DurableEvidenceCollector(EvidenceCollector):
    def __init__(self, runtime: DurableRuntime, task_id: str) -> None:
        self._runtime = runtime
        self._task_id = task_id

    def record(
        self,
        evidence_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        content: str | bytes | None = None,
        source: str = "worker",
        provenance: Mapping[str, Any] | None = None,
        artifact_reference: str | None = None,
        checksum: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        acquisition_method: EvidenceAcquisitionMethod = (
            EvidenceAcquisitionMethod.AGENT_REPORTED
        ),
        trust_level: EvidenceTrustLevel = EvidenceTrustLevel.AGENT_CLAIM,
        expires_at: datetime | None = None,
        evidence_id: str | None = None,
    ) -> EvidenceItem:
        del acquisition_method, trust_level
        item = EvidenceItem(
            evidence_id=evidence_id or self._runtime._id_factory(),
            type=evidence_type,
            source=source,
            collected_at=self._runtime._clock(),
            content=content,
            payload=payload,
            provenance=provenance or {},
            artifact_reference=artifact_reference,
            checksum=checksum,
            metadata=metadata or {},
            acquisition_method=EvidenceAcquisitionMethod.AGENT_REPORTED,
            trust_level=EvidenceTrustLevel.AGENT_CLAIM,
            expires_at=expires_at,
        )
        return self._runtime.add_evidence(self._task_id, item)

    def snapshot(self) -> EvidenceCollection:
        return self._runtime.store.evidence(self._task_id)


class _DurableEventEmitter(TaskEventEmitter):
    def __init__(self, runtime: DurableRuntime, task_id: str) -> None:
        self._runtime = runtime
        self._task_id = task_id

    def emit(
        self,
        name: str,
        details: Mapping[str, Any] | None = None,
        *,
        event_type: LifecycleEventType = LifecycleEventType.TASK_PROGRESS,
    ) -> None:
        if event_type not in {
            LifecycleEventType.TASK_PROGRESS,
            LifecycleEventType.TOOL_ACTION_REQUESTED,
            LifecycleEventType.WORKER_EVENT,
        }:
            raise ValueError("workers may emit only progress or tool/action events")
        event = self._runtime.store.append_event(
            self._task_id,
            event_type=event_type,
            occurred_at=self._runtime._clock(),
            name=name,
            details=details,
        )
        self._runtime._publish(event)


class _DurableCheckpointWriter:
    def __init__(self, runtime: DurableRuntime, task_id: str) -> None:
        self._runtime = runtime
        self._task_id = task_id

    def save(
        self,
        payload: Mapping[str, Any],
        *,
        label: str | None = None,
        checkpoint_id: str | None = None,
    ) -> str:
        resolved_id = checkpoint_id or self._runtime._id_factory()
        _, event = self._runtime.store.save_checkpoint(
            self._task_id,
            checkpoint_id=resolved_id,
            payload=payload,
            label=label,
            occurred_at=self._runtime._clock(),
        )
        if event is not None:
            self._runtime._publish(event)
        return resolved_id


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
