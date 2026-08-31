"""Durable persistence contracts and the default SQLite implementation."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Protocol, cast

from ._validation import require_non_empty
from .actions import (
    ActionConditionResult,
    ActionExecutionStatus,
    ActionPolicyDecision,
    ActionPostconditionStatus,
    ActionReceipt,
    ActionRequest,
    PreActionAuthorization,
    StoredAction,
)
from .approvals import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRevocation,
    ApprovalState,
    ApproverIdentity,
    StoredApproval,
)
from .contracts import CriterionEvaluation, RiskLevel, TaskContract, TaskStatus
from .core import (
    TaskError,
    TaskErrorCode,
    TaskResult,
    TaskTimestamps,
    WorkerReportedStatus,
)
from .evidence import (
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    _restore_evidence_origin,
    calculate_evidence_checksum,
)
from .recovery import (
    RecoveryApproval,
    RecoveryExecutionReceipt,
    RecoveryPlan,
    RecoveryStatus,
    RuntimeConfirmation,
)
from .serialization import JsonCodec, SafeJsonCodec, SerializationError
from .telemetry import LifecycleEvent, LifecycleEventType, task_contract_telemetry
from .verification import (
    ApprovalCriterion,
    CollectionNotEmptyCriterion,
    DeclaredConditionCriterion,
    FieldEqualsCriterion,
    RuntimeConfirmationCriterion,
    VerificationResult,
    VerificationStatus,
)

LATEST_SCHEMA_VERSION = 7
CONTRACT_SCHEMA_VERSION = 1


class PersistenceError(RuntimeError):
    """Base class for durable state errors."""


class TaskNotFoundError(PersistenceError):
    """Raised when a durable task ID does not exist."""


class TaskAlreadyExistsError(PersistenceError):
    """Raised when a durable task ID or idempotency key already exists."""


class ConcurrentUpdateError(PersistenceError):
    """Raised when optimistic locking detects a conflicting mutation."""


class InvalidTransitionError(PersistenceError):
    """Raised before an invalid state change can be committed."""


class CorruptStoreError(PersistenceError):
    """Raised when persisted state fails structural validation."""


class SchemaVersionError(PersistenceError):
    """Raised for an unsupported or malformed database schema version."""


@dataclass(frozen=True, slots=True)
class ContractSnapshot:
    """Safe, non-executable persisted representation of a task contract."""

    task_id: str
    objective: str
    input: Any
    acceptance_criteria: tuple[Mapping[str, Any], ...]
    required_evidence: tuple[Mapping[str, Any], ...]
    allowed_capabilities: tuple[str, ...]
    risk_level: str
    timeout_seconds: float
    idempotency_key: str
    metadata: Mapping[str, Any]
    schema_version: int = CONTRACT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "objective": self.objective,
            "input": self.input,
            "acceptance_criteria": list(self.acceptance_criteria),
            "required_evidence": list(self.required_evidence),
            "allowed_capabilities": list(self.allowed_capabilities),
            "risk_level": self.risk_level,
            "timeout_seconds": self.timeout_seconds,
            "idempotency_key": self.idempotency_key,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    checkpoint_id: str
    task_id: str
    label: str | None
    payload: Mapping[str, Any]
    task_version: int
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    task_id: str
    approval_key: str
    approved: bool | None
    approved_by: str | None
    reason: str
    created_at: datetime
    decided_at: datetime | None = None
    capability: str | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class RecoveryStateRecord:
    plan_id: str
    task_id: str
    status: str
    payload: Mapping[str, Any]
    version: int
    updated_at: datetime
    execution_owner_id: str | None = None
    receipt: Mapping[str, Any] | None = None
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    scope: str
    key: str
    owner_id: str
    status: str
    result: Any
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class StoredTask:
    """Complete durable task snapshot loaded independently of worker code."""

    task_id: str
    contract: ContractSnapshot
    contract_digest: str
    correlation_id: str
    worker_id: str
    status: TaskStatus
    reported_status: WorkerReportedStatus | None
    output: Any
    errors: tuple[TaskError, ...]
    verification: VerificationResult | None
    version: int
    execution_context_version: int
    wait_token: str | None
    timestamps: TaskTimestamps
    created_at: datetime
    updated_at: datetime

    @property
    def succeeded(self) -> bool:
        return self.status is TaskStatus.VERIFIED

    def to_result(self, evidence: EvidenceCollection) -> TaskResult[Any]:
        return TaskResult(
            task_id=self.task_id,
            correlation_id=self.correlation_id,
            status=self.status,
            reported_status=self.reported_status,
            output=self.output,
            evidence=evidence,
            errors=self.errors,
            timestamps=self.timestamps,
            final_verification_result=self.verification,
        )


_DURABLE_TRANSITIONS: Mapping[TaskStatus | None, frozenset[TaskStatus]] = {
    None: frozenset({TaskStatus.PENDING}),
    TaskStatus.PENDING: frozenset({TaskStatus.RUNNING, TaskStatus.FAILED}),
    TaskStatus.RUNNING: frozenset(
        {TaskStatus.AGENT_REPORTED_COMPLETE, TaskStatus.FAILED}
    ),
    TaskStatus.AGENT_REPORTED_COMPLETE: frozenset(
        {TaskStatus.VERIFYING, TaskStatus.AWAITING_APPROVAL}
    ),
    TaskStatus.VERIFYING: frozenset(
        {
            TaskStatus.VERIFIED,
            TaskStatus.FAILED,
            TaskStatus.INCONCLUSIVE,
            TaskStatus.AWAITING_EVIDENCE,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
        }
    ),
    TaskStatus.AWAITING_EVIDENCE: frozenset({TaskStatus.VERIFYING}),
    TaskStatus.AWAITING_APPROVAL: frozenset(
        {TaskStatus.VERIFYING, TaskStatus.AWAITING_RUNTIME_CONFIRMATION}
    ),
    TaskStatus.AWAITING_RUNTIME_CONFIRMATION: frozenset({TaskStatus.VERIFYING}),
    TaskStatus.INCONCLUSIVE: frozenset({TaskStatus.VERIFYING}),
    TaskStatus.VERIFIED: frozenset(),
    TaskStatus.FAILED: frozenset(
        {
            TaskStatus.VERIFYING,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
        }
    ),
}

_VERIFICATION_FINAL_STATUS: Mapping[VerificationStatus, TaskStatus] = {
    VerificationStatus.VERIFIED: TaskStatus.VERIFIED,
    VerificationStatus.FAILED: TaskStatus.FAILED,
    VerificationStatus.INCONCLUSIVE: TaskStatus.INCONCLUSIVE,
    VerificationStatus.AWAITING_EVIDENCE: TaskStatus.AWAITING_EVIDENCE,
    VerificationStatus.AWAITING_APPROVAL: TaskStatus.AWAITING_APPROVAL,
    VerificationStatus.AWAITING_RUNTIME_CONFIRMATION: (
        TaskStatus.AWAITING_RUNTIME_CONFIRMATION
    ),
}

_DURABLE_RECOVERY_TRANSITIONS: Mapping[
    RecoveryStatus | None,
    frozenset[RecoveryStatus],
] = {
    None: frozenset({RecoveryStatus.PLANNED}),
    RecoveryStatus.PLANNED: frozenset(
        {
            RecoveryStatus.AWAITING_PREFLIGHT_CONFIRMATION,
            RecoveryStatus.AWAITING_RUNTIME_CONFIRMATION,
            RecoveryStatus.APPROVAL_REQUIRED,
            RecoveryStatus.AWAITING_APPROVAL,
            RecoveryStatus.AUTHORIZED,
            RecoveryStatus.BLOCKED,
            RecoveryStatus.DRY_RUN,
        }
    ),
    RecoveryStatus.AWAITING_PREFLIGHT_CONFIRMATION: frozenset(
        {
            RecoveryStatus.AWAITING_APPROVAL,
            RecoveryStatus.AUTHORIZED,
            RecoveryStatus.BLOCKED,
            RecoveryStatus.DRY_RUN,
        }
    ),
    RecoveryStatus.AWAITING_RUNTIME_CONFIRMATION: frozenset(
        {
            RecoveryStatus.RUNTIME_CONFIRMED,
            RecoveryStatus.AUTHORIZED,
            RecoveryStatus.BLOCKED,
        }
    ),
    RecoveryStatus.APPROVAL_REQUIRED: frozenset(
        {
            RecoveryStatus.AWAITING_APPROVAL,
            RecoveryStatus.AUTHORIZED,
            RecoveryStatus.BLOCKED,
        }
    ),
    RecoveryStatus.AWAITING_APPROVAL: frozenset(
        {
            RecoveryStatus.AUTHORIZED,
            RecoveryStatus.BLOCKED,
            RecoveryStatus.DRY_RUN,
        }
    ),
    RecoveryStatus.AUTHORIZED: frozenset(),
    RecoveryStatus.EXECUTING: frozenset(),
    RecoveryStatus.EXECUTOR_SUCCEEDED: frozenset(
        {
            RecoveryStatus.POSTCONDITIONS_SATISFIED,
            RecoveryStatus.POSTCONDITION_FAILED,
        }
    ),
    RecoveryStatus.POSTCONDITIONS_SATISFIED: frozenset(
        {RecoveryStatus.VERIFIED, RecoveryStatus.FAILED}
    ),
    RecoveryStatus.DRY_RUN: frozenset(),
    RecoveryStatus.BLOCKED: frozenset(),
    RecoveryStatus.POSTCONDITION_FAILED: frozenset(),
    RecoveryStatus.VERIFIED: frozenset(),
    RecoveryStatus.UNKNOWN: frozenset(),
    RecoveryStatus.RUNTIME_CONFIRMED: frozenset(),
    RecoveryStatus.FAILED: frozenset(),
    RecoveryStatus.DUPLICATE_PREVENTED: frozenset(),
}


class PersistenceStore(Protocol):
    """Production-oriented durable state boundary used by ``DurableRuntime``."""

    def create_task(
        self,
        contract: TaskContract[Any, Any],
        *,
        correlation_id: str,
        worker_id: str,
        occurred_at: datetime,
    ) -> tuple[StoredTask, LifecycleEvent]: ...

    def load_task(self, task_id: str) -> StoredTask: ...

    def validate_contract(
        self,
        task_id: str,
        contract: TaskContract[Any, Any],
    ) -> None: ...

    def evidence(self, task_id: str) -> EvidenceCollection: ...

    def event_history(self, task_id: str) -> tuple[LifecycleEvent, ...]: ...

    def transition(
        self,
        task_id: str,
        *,
        expected_version: int,
        next_status: TaskStatus,
        occurred_at: datetime,
        details: Mapping[str, Any] | None = None,
        dedupe_key: str | None = None,
    ) -> tuple[StoredTask, LifecycleEvent]: ...

    def append_event(
        self,
        task_id: str,
        *,
        event_type: LifecycleEventType,
        occurred_at: datetime,
        name: str | None = None,
        details: Mapping[str, Any] | None = None,
        dedupe_key: str | None = None,
    ) -> LifecycleEvent: ...

    def append_event_once(
        self,
        task_id: str,
        *,
        event_type: LifecycleEventType,
        occurred_at: datetime,
        name: str | None = None,
        details: Mapping[str, Any] | None = None,
        dedupe_key: str,
    ) -> tuple[LifecycleEvent, bool]: ...

    def record_evidence(
        self,
        task_id: str,
        item: EvidenceItem,
    ) -> tuple[EvidenceItem, LifecycleEvent | None]: ...

    def record_worker_report(
        self,
        task_id: str,
        *,
        expected_version: int,
        reported_status: WorkerReportedStatus,
        output: Any,
        errors: Sequence[TaskError],
        occurred_at: datetime,
    ) -> tuple[StoredTask, tuple[LifecycleEvent, ...]]: ...

    def record_runtime_failure(
        self,
        task_id: str,
        *,
        expected_version: int,
        errors: Sequence[TaskError],
        occurred_at: datetime,
        reason: str,
    ) -> tuple[StoredTask, tuple[LifecycleEvent, ...]]: ...

    def record_verification(
        self,
        task_id: str,
        *,
        expected_version: int,
        result: VerificationResult,
        final_status: TaskStatus,
        errors: Sequence[TaskError],
        occurred_at: datetime,
        wait_token: str | None,
    ) -> tuple[StoredTask, tuple[LifecycleEvent, ...]]: ...

    def save_checkpoint(
        self,
        task_id: str,
        *,
        checkpoint_id: str,
        payload: Mapping[str, Any],
        label: str | None,
        occurred_at: datetime,
    ) -> tuple[CheckpointRecord, LifecycleEvent | None]: ...

    def latest_checkpoint(self, task_id: str) -> CheckpointRecord | None: ...

    def checkpoints(self, task_id: str) -> tuple[CheckpointRecord, ...]: ...

    def claim_checkpoint_resume(
        self,
        task_id: str,
        *,
        checkpoint_id: str,
        expected_version: int,
        occurred_at: datetime,
    ) -> LifecycleEvent: ...

    def request_approval(
        self,
        task_id: str,
        *,
        approval_id: str,
        approval_key: str,
        reason: str,
        occurred_at: datetime,
    ) -> tuple[ApprovalRecord, LifecycleEvent | None]: ...

    def decide_approval(
        self,
        task_id: str,
        *,
        approval_key: str,
        approved: bool,
        approved_by: str,
        reason: str,
        occurred_at: datetime,
        approval_id: str,
        capability: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[ApprovalRecord, LifecycleEvent | None]: ...

    def approval_values(
        self,
        task_id: str,
        *,
        occurred_at: datetime | None = None,
    ) -> dict[str, bool]: ...

    def approvals(self, task_id: str) -> tuple[ApprovalRecord, ...]: ...

    def create_approval_request(
        self,
        request: ApprovalRequest,
    ) -> tuple[StoredApproval, LifecycleEvent | None]: ...

    def record_approval_decision(
        self,
        decision: ApprovalDecision,
    ) -> tuple[StoredApproval, LifecycleEvent | None]: ...

    def revoke_approval(
        self,
        revocation: ApprovalRevocation,
    ) -> tuple[StoredApproval, LifecycleEvent | None]: ...

    def load_approval(self, approval_id: str) -> StoredApproval: ...

    def find_approval(
        self,
        task_id: str,
        *,
        target_hash: str,
        required_scope: str,
        occurred_at: datetime,
    ) -> StoredApproval | None: ...

    def consume_approval(
        self,
        approval_id: str,
        *,
        request_hash: str,
        required_scope: str,
        consumed_by: str,
        occurred_at: datetime,
    ) -> StoredApproval: ...

    def save_runtime_confirmation(
        self,
        task_id: str,
        confirmation: RuntimeConfirmation,
    ) -> LifecycleEvent | None: ...

    def runtime_confirmation_values(self, task_id: str) -> dict[str, bool]: ...

    def runtime_confirmations(
        self,
        task_id: str,
    ) -> tuple[RuntimeConfirmation, ...]: ...

    def save_recovery_state(
        self,
        plan: RecoveryPlan,
        *,
        status: str,
        occurred_at: datetime,
        expected_version: int | None = None,
    ) -> RecoveryStateRecord: ...

    def load_recovery_state(self, plan_id: str) -> RecoveryStateRecord | None: ...

    def claim_recovery_execution(
        self,
        plan: RecoveryPlan,
        *,
        expected_version: int,
        owner_id: str,
        occurred_at: datetime,
        approval_id: str | None = None,
        approval_request_hash: str | None = None,
        approval_scope: str | None = None,
    ) -> tuple[RecoveryStateRecord, LifecycleEvent]: ...

    def finish_recovery_execution(
        self,
        plan: RecoveryPlan,
        *,
        expected_version: int,
        owner_id: str,
        receipt: RecoveryExecutionReceipt,
    ) -> tuple[RecoveryStateRecord, LifecycleEvent]: ...

    def mark_recovery_unknown(
        self,
        plan: RecoveryPlan,
        *,
        expected_version: int,
        occurred_at: datetime,
        reason: str,
    ) -> tuple[RecoveryStateRecord, LifecycleEvent]: ...

    def link_recovery_evidence(
        self,
        plan_id: str,
        evidence_id: str,
        *,
        postcondition_name: str,
        occurred_at: datetime,
    ) -> LifecycleEvent: ...

    def recovery_evidence(self, plan_id: str) -> EvidenceCollection: ...

    def record_recovery_evidence(
        self,
        plan_id: str,
        *,
        postcondition_name: str,
        item: EvidenceItem,
        occurred_at: datetime,
    ) -> tuple[EvidenceItem, tuple[LifecycleEvent, ...]]: ...

    def reserve_idempotency(
        self,
        *,
        scope: str,
        key: str,
        owner_id: str,
        occurred_at: datetime,
    ) -> IdempotencyRecord: ...

    def complete_idempotency(
        self,
        *,
        scope: str,
        key: str,
        owner_id: str,
        result: Any,
        occurred_at: datetime,
    ) -> None: ...

    def idempotency_record(
        self,
        *,
        scope: str,
        key: str,
    ) -> IdempotencyRecord | None: ...

    def continuation_token(self, task_id: str, status: TaskStatus) -> str: ...

    def prepare_action(
        self,
        request: ActionRequest,
        *,
        dry_run: bool,
        occurred_at: datetime,
    ) -> tuple[StoredAction, bool, LifecycleEvent | None]: ...

    def load_action(self, action_id: str) -> StoredAction: ...

    def record_action_policy(
        self,
        action_id: str,
        *,
        expected_version: int,
        decision: ActionPolicyDecision,
    ) -> tuple[StoredAction, LifecycleEvent]: ...

    def record_action_authorization(
        self,
        action_id: str,
        *,
        expected_version: int,
        authorization: PreActionAuthorization,
    ) -> tuple[StoredAction, LifecycleEvent]: ...

    def mark_action_executing(
        self,
        action_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
        owner_id: str,
        approval_id: str | None = None,
        approval_request_hash: str | None = None,
        approval_scope: str | None = None,
    ) -> tuple[StoredAction, LifecycleEvent]: ...

    def finish_action(
        self,
        action_id: str,
        *,
        expected_version: int,
        receipt: ActionReceipt,
    ) -> tuple[StoredAction, LifecycleEvent]: ...

    def complete_action_postconditions(
        self,
        action_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
    ) -> tuple[StoredAction, LifecycleEvent]: ...

    def mark_action_unknown(
        self,
        action_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
        reason: str,
    ) -> tuple[StoredAction, LifecycleEvent]: ...

    def link_action_evidence(
        self,
        action_id: str,
        evidence_id: str,
        *,
        postcondition_name: str,
        occurred_at: datetime,
    ) -> LifecycleEvent: ...

    def complete_action_postcondition(
        self,
        action_id: str,
        *,
        postcondition_name: str,
        items: Sequence[EvidenceItem],
        occurred_at: datetime,
    ) -> tuple[LifecycleEvent, ...]: ...

    def action_evidence(self, action_id: str) -> EvidenceCollection: ...

    def completed_action_postconditions(self, action_id: str) -> frozenset[str]: ...


class SQLiteStore:
    """Transactional, WAL-enabled default durable local store."""

    def __init__(
        self,
        path: str | Path = Path("./runmantle.db"),
        *,
        codec: JsonCodec | None = None,
        busy_timeout_ms: int = 5000,
        target_schema_version: int = LATEST_SCHEMA_VERSION,
    ) -> None:
        if target_schema_version < 1 or target_schema_version > LATEST_SCHEMA_VERSION:
            raise SchemaVersionError("unsupported target schema version")
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("SQLiteStore requires a filesystem path for durability")
        self.codec = codec or SafeJsonCodec()
        self.busy_timeout_ms = busy_timeout_ms
        self._initialization_lock = Lock()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize(target_schema_version)

    @property
    def schema_version(self) -> int:
        with self._connect() as connection:
            row = connection.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row is not None else 0

    def create_task(
        self,
        contract: TaskContract[Any, Any],
        *,
        correlation_id: str,
        worker_id: str,
        occurred_at: datetime,
    ) -> tuple[StoredTask, LifecycleEvent]:
        snapshot = contract_snapshot(contract, self.codec)
        encoded_contract = self.codec.dumps(snapshot.to_dict())
        digest = hashlib.sha256(encoded_contract.encode("utf-8")).hexdigest()
        timestamp = _iso(occurred_at)
        with self._transaction() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO tasks(
                        task_id, contract_json, contract_digest, correlation_id,
                        worker_id, current_state, version, created_at, updated_at,
                        pending_at, errors_json
                    ) VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        contract.task_id,
                        encoded_contract,
                        digest,
                        correlation_id,
                        worker_id,
                        TaskStatus.PENDING.value,
                        timestamp,
                        timestamp,
                        timestamp,
                        self.codec.dumps([]),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise TaskAlreadyExistsError(
                    f"durable task {contract.task_id!r} already exists"
                ) from error
            event = self._insert_event(
                connection,
                task_id=contract.task_id,
                event_type=LifecycleEventType.STATE_TRANSITION,
                correlation_id=correlation_id,
                worker_id=worker_id,
                occurred_at=occurred_at,
                state=TaskStatus.PENDING,
                previous_state=None,
                details={
                    "task_contract": task_contract_telemetry(contract),
                    "risk_level": contract.risk_level,
                },
                dedupe_key="task-created",
            )
        return self.load_task(contract.task_id), event

    def load_task(self, task_id: str) -> StoredTask:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"durable task {task_id!r} does not exist")
        return self._stored_task(row)

    def validate_contract(
        self,
        task_id: str,
        contract: TaskContract[Any, Any],
    ) -> None:
        stored = self.load_task(task_id)
        snapshot = contract_snapshot(contract, self.codec)
        encoded = self.codec.dumps(snapshot.to_dict())
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if digest != stored.contract_digest:
            raise PersistenceError("supplied contract differs from persisted contract")

    def transition(
        self,
        task_id: str,
        *,
        expected_version: int,
        next_status: TaskStatus,
        occurred_at: datetime,
        details: Mapping[str, Any] | None = None,
        dedupe_key: str | None = None,
    ) -> tuple[StoredTask, LifecycleEvent]:
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            current = self._status(row["current_state"])
            if next_status is TaskStatus.VERIFIED:
                raise InvalidTransitionError(
                    "VERIFIED must be committed through record_verification"
                )
            if int(row["version"]) != expected_version:
                raise ConcurrentUpdateError(
                    f"task {task_id!r} changed from version {expected_version}"
                )
            if dedupe_key is not None:
                existing = self._event_by_dedupe(connection, task_id, dedupe_key)
                if existing is not None:
                    existing_event = self._event(existing)
                    if existing_event.state is not next_status:
                        raise ConcurrentUpdateError(
                            "transition dedupe key was reused for a different state"
                        )
                    return self._stored_task(row), existing_event
            if next_status not in _DURABLE_TRANSITIONS[current]:
                raise InvalidTransitionError(
                    f"invalid durable transition from {current.value} "
                    f"to {next_status.value}"
                )
            if current is TaskStatus.FAILED and next_status is TaskStatus.VERIFYING:
                recovery_plan_id = (details or {}).get("recovery_plan_id")
                recovery = (
                    None
                    if not isinstance(recovery_plan_id, str)
                    else connection.execute(
                        """
                        SELECT task_id, status FROM recovery_state
                        WHERE plan_id = ?
                        """,
                        (recovery_plan_id,),
                    ).fetchone()
                )
                if (
                    recovery is None
                    or str(recovery["task_id"]) != task_id
                    or str(recovery["status"])
                    != RecoveryStatus.POSTCONDITIONS_SATISFIED.value
                ):
                    raise InvalidTransitionError(
                        "failed task can re-enter verification only from a "
                        "satisfied durable recovery boundary"
                    )
            timestamp_column = _timestamp_column(next_status)
            assignments = [
                "current_state = ?",
                "version = version + 1",
                "execution_context_version = execution_context_version + 1",
                "updated_at = ?",
            ]
            values: list[Any] = [next_status.value, _iso(occurred_at)]
            if current is TaskStatus.FAILED and next_status in {
                TaskStatus.VERIFYING,
                TaskStatus.AWAITING_APPROVAL,
                TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
            }:
                assignments.append("finished_at = NULL")
            if timestamp_column is not None:
                assignments.append(
                    f"{timestamp_column} = COALESCE({timestamp_column}, ?)"
                )
                values.append(_iso(occurred_at))
            values.extend((task_id, expected_version))
            cursor = connection.execute(
                f"UPDATE tasks SET {', '.join(assignments)} "
                "WHERE task_id = ? AND version = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise ConcurrentUpdateError(f"task {task_id!r} changed concurrently")
            event = self._insert_task_event(
                connection,
                row,
                event_type=LifecycleEventType.STATE_TRANSITION,
                occurred_at=occurred_at,
                state=next_status,
                previous_state=current,
                details=details or {},
                dedupe_key=dedupe_key,
            )
        return self.load_task(task_id), event

    def append_event(
        self,
        task_id: str,
        *,
        event_type: LifecycleEventType,
        occurred_at: datetime,
        name: str | None = None,
        details: Mapping[str, Any] | None = None,
        dedupe_key: str | None = None,
    ) -> LifecycleEvent:
        event, _ = self._append_event_once(
            task_id,
            event_type=event_type,
            occurred_at=occurred_at,
            name=name,
            details=details,
            dedupe_key=dedupe_key,
        )
        return event

    def append_event_once(
        self,
        task_id: str,
        *,
        event_type: LifecycleEventType,
        occurred_at: datetime,
        name: str | None = None,
        details: Mapping[str, Any] | None = None,
        dedupe_key: str,
    ) -> tuple[LifecycleEvent, bool]:
        """Append a deduplicated event and report whether this call inserted it."""

        return self._append_event_once(
            task_id,
            event_type=event_type,
            occurred_at=occurred_at,
            name=name,
            details=details,
            dedupe_key=dedupe_key,
        )

    def _append_event_once(
        self,
        task_id: str,
        *,
        event_type: LifecycleEventType,
        occurred_at: datetime,
        name: str | None,
        details: Mapping[str, Any] | None,
        dedupe_key: str | None,
    ) -> tuple[LifecycleEvent, bool]:
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            if dedupe_key is not None:
                existing = self._event_by_dedupe(connection, task_id, dedupe_key)
                if existing is not None:
                    existing_event = self._event(existing)
                    if existing_event.event_type is not event_type:
                        raise ConcurrentUpdateError(
                            "event dedupe key was reused for a different event type"
                        )
                    return existing_event, False
            return (
                self._insert_task_event(
                    connection,
                    row,
                    event_type=event_type,
                    occurred_at=occurred_at,
                    name=name,
                    details=details or {},
                    dedupe_key=dedupe_key,
                ),
                True,
            )

    def record_evidence(
        self,
        task_id: str,
        item: EvidenceItem,
    ) -> tuple[EvidenceItem, LifecycleEvent | None]:
        encoded = self.codec.dumps(_evidence_dict(item))
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            status = self._status(row["current_state"])
            if status in {TaskStatus.VERIFIED, TaskStatus.FAILED}:
                raise InvalidTransitionError(
                    f"cannot add evidence after task became {status.value}"
                )
            existing = connection.execute(
                "SELECT item_json FROM evidence WHERE task_id = ? AND evidence_id = ?",
                (task_id, item.evidence_id),
            ).fetchone()
            if existing is not None:
                if str(existing["item_json"]) != encoded:
                    raise ConcurrentUpdateError(
                        f"evidence ID {item.evidence_id!r} has conflicting content"
                    )
                return item, None
            connection.execute(
                "UPDATE tasks SET version = version + 1, "
                + (
                    "execution_context_version = execution_context_version + 1, "
                    if "execution_context_version" in row.keys()
                    else ""
                )
                + "updated_at = ? WHERE task_id = ?",
                (_iso(item.collected_at), task_id),
            )
            event = self._insert_evidence(connection, row, item, encoded)
        return item, event

    def evidence(self, task_id: str) -> EvidenceCollection:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT item_json FROM evidence
                WHERE task_id = ? ORDER BY collected_at, evidence_id
                """,
                (task_id,),
            ).fetchall()
        try:
            return EvidenceCollection(
                tuple(self._evidence(str(row["item_json"])) for row in rows)
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            raise CorruptStoreError("persisted evidence is invalid") from error

    def event_history(self, task_id: str) -> tuple[LifecycleEvent, ...]:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE task_id = ? ORDER BY sequence",
                (task_id,),
            ).fetchall()
        try:
            return tuple(self._event(row) for row in rows)
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            raise CorruptStoreError("persisted lifecycle event is invalid") from error

    def record_worker_report(
        self,
        task_id: str,
        *,
        expected_version: int,
        reported_status: WorkerReportedStatus,
        output: Any,
        errors: Sequence[TaskError],
        occurred_at: datetime,
    ) -> tuple[StoredTask, tuple[LifecycleEvent, ...]]:
        next_status = (
            TaskStatus.AGENT_REPORTED_COMPLETE
            if reported_status is WorkerReportedStatus.COMPLETED
            else TaskStatus.FAILED
        )
        encoded_output = self.codec.dumps(output) if output is not None else None
        encoded_errors = self.codec.dumps([_error_dict(item) for item in errors])
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            current = self._status(row["current_state"])
            if int(row["version"]) != expected_version:
                raise ConcurrentUpdateError(f"task {task_id!r} changed concurrently")
            if next_status not in _DURABLE_TRANSITIONS[current]:
                raise InvalidTransitionError(
                    f"cannot record worker report while task is {current.value}"
                )
            connection.execute(
                """
                UPDATE tasks
                SET current_state = ?, reported_status = ?, output_json = ?,
                    errors_json = ?, version = version + 1,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ?,
                    agent_reported_complete_at = CASE WHEN ? = ? THEN ?
                        ELSE agent_reported_complete_at END,
                    finished_at = CASE WHEN ? = ? THEN ? ELSE finished_at END
                WHERE task_id = ? AND version = ?
                """,
                (
                    next_status.value,
                    reported_status.value,
                    encoded_output,
                    encoded_errors,
                    _iso(occurred_at),
                    next_status.value,
                    TaskStatus.AGENT_REPORTED_COMPLETE.value,
                    _iso(occurred_at),
                    next_status.value,
                    TaskStatus.FAILED.value,
                    _iso(occurred_at),
                    task_id,
                    expected_version,
                ),
            )
            semantic_type = (
                LifecycleEventType.WORKER_COMPLETED
                if reported_status is WorkerReportedStatus.COMPLETED
                else LifecycleEventType.WORKER_FAILED
            )
            events = [
                self._insert_task_event(
                    connection,
                    row,
                    event_type=semantic_type,
                    occurred_at=occurred_at,
                    state=current,
                    name=semantic_type.value,
                    details={"reported_status": reported_status},
                    dedupe_key="worker-report",
                ),
                self._insert_task_event(
                    connection,
                    row,
                    event_type=LifecycleEventType.STATE_TRANSITION,
                    occurred_at=occurred_at,
                    state=next_status,
                    previous_state=current,
                    details={"reported_status": reported_status},
                    dedupe_key="worker-report-transition",
                ),
            ]
            if reported_status is WorkerReportedStatus.COMPLETED:
                events.append(
                    self._insert_task_event(
                        connection,
                        row,
                        event_type=LifecycleEventType.AGENT_REPORTED_COMPLETION,
                        occurred_at=occurred_at,
                        state=next_status,
                        name="agent.reported_completion",
                        details={},
                        dedupe_key="agent-reported-completion",
                    )
                )
        return self.load_task(task_id), tuple(events)

    def record_runtime_failure(
        self,
        task_id: str,
        *,
        expected_version: int,
        errors: Sequence[TaskError],
        occurred_at: datetime,
        reason: str,
    ) -> tuple[StoredTask, tuple[LifecycleEvent, ...]]:
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            current = self._status(row["current_state"])
            if int(row["version"]) != expected_version:
                raise ConcurrentUpdateError(f"task {task_id!r} changed concurrently")
            if TaskStatus.FAILED not in _DURABLE_TRANSITIONS[current]:
                raise InvalidTransitionError(
                    f"cannot fail task while it is {current.value}"
                )
            connection.execute(
                """
                UPDATE tasks SET current_state = ?, errors_json = ?,
                    version = version + 1,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ?, finished_at = ?
                WHERE task_id = ? AND version = ?
                """,
                (
                    TaskStatus.FAILED.value,
                    self.codec.dumps([_error_dict(item) for item in errors]),
                    _iso(occurred_at),
                    _iso(occurred_at),
                    task_id,
                    expected_version,
                ),
            )
            events = (
                self._insert_task_event(
                    connection,
                    row,
                    event_type=LifecycleEventType.WORKER_FAILED,
                    occurred_at=occurred_at,
                    state=current,
                    name="worker.failed",
                    details={"reason": reason},
                    dedupe_key=f"runtime-failure:{expected_version}",
                ),
                self._insert_task_event(
                    connection,
                    row,
                    event_type=LifecycleEventType.STATE_TRANSITION,
                    occurred_at=occurred_at,
                    state=TaskStatus.FAILED,
                    previous_state=current,
                    details={"reason": reason},
                    dedupe_key=f"runtime-failure-transition:{expected_version}",
                ),
                self._insert_task_event(
                    connection,
                    row,
                    event_type=LifecycleEventType.TASK_FAILED,
                    occurred_at=occurred_at,
                    state=TaskStatus.FAILED,
                    name="task.failed",
                    details={"reason": reason},
                    dedupe_key=f"task-failed:{expected_version}",
                ),
            )
        return self.load_task(task_id), events

    def record_verification(
        self,
        task_id: str,
        *,
        expected_version: int,
        result: VerificationResult,
        final_status: TaskStatus,
        errors: Sequence[TaskError],
        occurred_at: datetime,
        wait_token: str | None,
    ) -> tuple[StoredTask, tuple[LifecycleEvent, ...]]:
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            current = self._status(row["current_state"])
            if int(row["version"]) != expected_version:
                raise ConcurrentUpdateError(f"task {task_id!r} changed concurrently")
            if final_status not in _DURABLE_TRANSITIONS[current]:
                raise InvalidTransitionError(
                    f"cannot finish verification while task is {current.value}"
                )
            expected_final_status = _VERIFICATION_FINAL_STATUS[result.status]
            if final_status is not expected_final_status:
                raise InvalidTransitionError(
                    "verification result status does not match final task status"
                )
            if final_status is TaskStatus.VERIFIED:
                self._require_trusted_verification_evidence(
                    connection,
                    row,
                    decision_time=occurred_at,
                )
            finished_at = (
                _iso(occurred_at)
                if final_status in {TaskStatus.VERIFIED, TaskStatus.FAILED}
                else None
            )
            connection.execute(
                """
                UPDATE tasks
                SET current_state = ?, verification_json = ?, errors_json = ?,
                    wait_token = ?, version = version + 1,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ?,
                    finished_at = ?
                WHERE task_id = ? AND version = ?
                """,
                (
                    final_status.value,
                    self.codec.dumps(_verification_dict(result)),
                    self.codec.dumps([_error_dict(item) for item in errors]),
                    wait_token,
                    _iso(occurred_at),
                    finished_at,
                    task_id,
                    expected_version,
                ),
            )
            events = (
                self._insert_task_event(
                    connection,
                    row,
                    event_type=LifecycleEventType.VERIFICATION_RESULT,
                    occurred_at=occurred_at,
                    state=current,
                    name="verification.result",
                    details={
                        "status": result.status,
                        "missing_evidence": result.missing_evidence,
                        "contradictory_evidence": result.contradictory_evidence,
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
                            for item in result.criteria
                        ],
                    },
                    dedupe_key=f"verification-result:{expected_version}",
                ),
                self._insert_task_event(
                    connection,
                    row,
                    event_type=LifecycleEventType.STATE_TRANSITION,
                    occurred_at=occurred_at,
                    state=final_status,
                    previous_state=current,
                    details={"verification_status": result.status},
                    dedupe_key=f"verification-transition:{expected_version}",
                ),
            )
        return self.load_task(task_id), events

    def _require_trusted_verification_evidence(
        self,
        connection: sqlite3.Connection,
        task: sqlite3.Row,
        *,
        decision_time: datetime,
    ) -> None:
        """Recheck the global evidence invariant at the authoritative commit."""

        try:
            contract_value = self.codec.loads(str(task["contract_json"]))
            if not isinstance(contract_value, Mapping):
                raise CorruptStoreError("persisted task contract is not an object")
            snapshot = _contract_snapshot(contract_value)
            requirements = tuple(
                EvidenceRequirement(
                    evidence_type=str(value["evidence_type"]),
                    description=str(value["description"]),
                    minimum_count=int(value["minimum_count"]),
                    consistent_fields=tuple(
                        str(item) for item in value.get("consistent_fields", [])
                    ),
                    minimum_trust_level=EvidenceTrustLevel(
                        int(value["minimum_trust_level"])
                    ),
                    max_age=(
                        None
                        if value.get("max_age_seconds") is None
                        else timedelta(seconds=float(value["max_age_seconds"]))
                    ),
                )
                for value in snapshot.required_evidence
            )
            evidence_rows = connection.execute(
                """
                SELECT item_json FROM evidence
                WHERE task_id = ? ORDER BY collected_at, evidence_id
                """,
                (str(task["task_id"]),),
            ).fetchall()
            evidence = tuple(
                self._evidence(str(evidence_row["item_json"]))
                for evidence_row in evidence_rows
            )
        except (KeyError, TypeError, ValueError, SerializationError) as error:
            if isinstance(error, CorruptStoreError):
                raise
            raise CorruptStoreError(
                "persisted verification inputs are invalid"
            ) from error

        if not any(
            requirement.minimum_trust_level >= EvidenceTrustLevel.RUNTIME_OBSERVED
            for requirement in requirements
        ):
            raise InvalidTransitionError(
                "VERIFIED requires an explicit runtime-observed or independent "
                "evidence requirement"
            )
        missing = tuple(
            requirement.evidence_type
            for requirement in requirements
            if sum(
                1 for item in evidence if requirement.accepts(item, at=decision_time)
            )
            < requirement.minimum_count
        )
        if missing:
            raise InvalidTransitionError(
                "VERIFIED requires adequate persisted trusted evidence: "
                + ", ".join(missing)
            )

    def save_checkpoint(
        self,
        task_id: str,
        *,
        checkpoint_id: str,
        payload: Mapping[str, Any],
        label: str | None,
        occurred_at: datetime,
    ) -> tuple[CheckpointRecord, LifecycleEvent | None]:
        encoded = self.codec.dumps(dict(payload))
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            status = self._status(row["current_state"])
            if status is not TaskStatus.RUNNING:
                raise InvalidTransitionError(
                    "checkpoints may only be saved at explicit RUNNING boundaries"
                )
            existing = connection.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["task_id"]) != task_id
                    or str(existing["payload_json"]) != encoded
                    or _optional_str(existing["label"]) != label
                ):
                    raise ConcurrentUpdateError("checkpoint ID has conflicting content")
                return self._checkpoint(existing), None
            new_version = int(row["version"]) + 1
            connection.execute(
                """
                INSERT INTO checkpoints(
                    checkpoint_id, task_id, label, payload_json,
                    task_version, created_at
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint_id,
                    task_id,
                    label,
                    encoded,
                    new_version,
                    _iso(occurred_at),
                ),
            )
            connection.execute(
                """UPDATE tasks SET version = ?,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ? WHERE task_id = ?""",
                (new_version, _iso(occurred_at), task_id),
            )
            event = self._insert_task_event(
                connection,
                row,
                event_type=LifecycleEventType.CHECKPOINT_SAVED,
                occurred_at=occurred_at,
                state=status,
                name="checkpoint.saved",
                details={"checkpoint_id": checkpoint_id, "label": label},
                dedupe_key=f"checkpoint:{checkpoint_id}",
            )
            checkpoint = CheckpointRecord(
                checkpoint_id=checkpoint_id,
                task_id=task_id,
                label=label,
                payload=dict(payload),
                task_version=new_version,
                created_at=occurred_at,
            )
        return checkpoint, event

    def latest_checkpoint(self, task_id: str) -> CheckpointRecord | None:
        self.load_task(task_id)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM checkpoints WHERE task_id = ?
                ORDER BY task_version DESC, created_at DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
        return self._checkpoint(row) if row is not None else None

    def checkpoints(self, task_id: str) -> tuple[CheckpointRecord, ...]:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM checkpoints WHERE task_id = ?
                ORDER BY task_version, created_at
                """,
                (task_id,),
            ).fetchall()
        return tuple(self._checkpoint(row) for row in rows)

    def claim_checkpoint_resume(
        self,
        task_id: str,
        *,
        checkpoint_id: str,
        expected_version: int,
        occurred_at: datetime,
    ) -> LifecycleEvent:
        key = f"{task_id}:{checkpoint_id}"
        with self._transaction() as connection:
            row = self._task_row(connection, task_id)
            if self._status(row["current_state"]) is not TaskStatus.RUNNING:
                raise InvalidTransitionError(
                    "only a RUNNING task can resume a checkpoint"
                )
            if int(row["version"]) != expected_version:
                raise ConcurrentUpdateError(f"task {task_id!r} changed concurrently")
            checkpoint = connection.execute(
                "SELECT task_id FROM checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
            if checkpoint is None or str(checkpoint["task_id"]) != task_id:
                raise InvalidTransitionError(
                    "checkpoint does not belong to the task being resumed"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO idempotency_records(
                        scope, idempotency_key, owner_id, status, result_json,
                        created_at, updated_at
                    ) VALUES('checkpoint-resume', ?, ?, 'reserved', NULL, ?, ?)
                    """,
                    (key, task_id, _iso(occurred_at), _iso(occurred_at)),
                )
            except sqlite3.IntegrityError as error:
                raise ConcurrentUpdateError(
                    "checkpoint resume is already claimed"
                ) from error
            connection.execute(
                """
                UPDATE tasks SET version = version + 1,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ?
                WHERE task_id = ? AND version = ?
                """,
                (_iso(occurred_at), task_id, expected_version),
            )
            return self._insert_task_event(
                connection,
                row,
                event_type=LifecycleEventType.TASK_RESUMED,
                occurred_at=occurred_at,
                state=TaskStatus.RUNNING,
                name="task.resumed",
                details={"checkpoint_id": checkpoint_id},
                dedupe_key=f"resume:{checkpoint_id}",
            )

    def request_approval(
        self,
        task_id: str,
        *,
        approval_id: str,
        approval_key: str,
        reason: str,
        occurred_at: datetime,
    ) -> tuple[ApprovalRecord, LifecycleEvent | None]:
        request = ApprovalRequest(
            approval_id=approval_id,
            task_id=task_id,
            target_id=approval_key,
            target_hash=approval_key,
            required_scope="legacy.approval",
            risk_level=RiskLevel.LOW,
            reason=reason,
            created_at=occurred_at,
            expires_at=datetime.max.replace(tzinfo=UTC),
            one_time_use=False,
            metadata={"legacy_api": True},
        )
        stored, event = self.create_approval_request(request)
        return self._approval_record_from_stored(stored), event

    def decide_approval(
        self,
        task_id: str,
        *,
        approval_key: str,
        approved: bool,
        approved_by: str,
        reason: str,
        occurred_at: datetime,
        approval_id: str,
        capability: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[ApprovalRecord, LifecycleEvent | None]:
        try:
            pending = self.load_approval(approval_id)
        except TaskNotFoundError:
            request = ApprovalRequest(
                approval_id=approval_id,
                task_id=task_id,
                target_id=approval_key,
                target_hash=approval_key,
                required_scope="legacy.approval",
                risk_level=RiskLevel.LOW,
                reason=reason,
                created_at=occurred_at,
                expires_at=datetime.max.replace(tzinfo=UTC),
                one_time_use=False,
                metadata={"legacy_api": True},
            )
            pending, _ = self.create_approval_request(request)
        if (
            pending.request.task_id != task_id
            or pending.request.target_hash != approval_key
        ):
            raise ConcurrentUpdateError(
                "approval decision conflicts with persisted request"
            )
        decision = ApprovalDecision(
            decision_id=f"legacy-decision:{approval_id}",
            approval_id=approval_id,
            request_hash=pending.request.request_hash,
            approved=approved,
            approver=ApproverIdentity(
                subject=approved_by,
                issuer="legacy-unverified",
                authenticated_at=occurred_at,
                authentication_method="legacy-string",
                claims={"legacy_api": True},
            ),
            decided_at=occurred_at,
            reason=reason,
            metadata={
                "legacy_api": True,
                "capability": capability,
                "idempotency_key": idempotency_key,
            },
        )
        stored, event = self.record_approval_decision(decision)
        if capability is not None or idempotency_key is not None:
            with self._transaction() as connection:
                connection.execute(
                    """
                    UPDATE approvals SET capability = ?, idempotency_key = ?
                    WHERE approval_id = ?
                    """,
                    (capability, idempotency_key, approval_id),
                )
        return self._approval_record_from_stored(
            stored,
            capability=capability,
            idempotency_key=idempotency_key,
        ), event

    def approval_values(
        self,
        task_id: str,
        *,
        occurred_at: datetime | None = None,
    ) -> dict[str, bool]:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM approvals
                WHERE task_id = ? AND approved IS NOT NULL
                ORDER BY decided_at, approval_id
                """,
                (task_id,),
            ).fetchall()
        now = occurred_at or datetime.now(UTC)
        values: dict[str, bool] = {}
        for row in rows:
            stored = self._stored_approval(row)
            state = stored.state_at(now)
            if state in {ApprovalState.APPROVED, ApprovalState.REJECTED}:
                assert stored.decision is not None
                values[stored.request.target_hash] = stored.decision.approved
        return values

    def approvals(self, task_id: str) -> tuple[ApprovalRecord, ...]:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM approvals WHERE task_id = ?
                ORDER BY created_at, approval_id
                """,
                (task_id,),
            ).fetchall()
        return tuple(self._approval(row) for row in rows)

    def create_approval_request(
        self,
        request: ApprovalRequest,
    ) -> tuple[StoredApproval, LifecycleEvent | None]:
        """Persist an immutable, exact-target approval request."""

        with self._transaction() as connection:
            task = self._task_row(connection, request.task_id)
            if self._status(task["current_state"]) is TaskStatus.VERIFIED:
                raise InvalidTransitionError(
                    "cannot request approval after task verification"
                )
            existing = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (request.approval_id,),
            ).fetchone()
            if existing is not None:
                stored = self._stored_approval(existing)
                if stored.request.request_hash != request.request_hash:
                    raise ConcurrentUpdateError(
                        "approval request ID has conflicting immutable content"
                    )
                return stored, None
            connection.execute(
                """
                INSERT INTO approvals(
                    approval_id, task_id, approval_key, approved, approved_by,
                    reason, created_at, decided_at, capability, idempotency_key,
                    target_id, target_hash, request_hash, required_scope,
                    risk_level, request_reason, expires_at, one_time_use,
                    request_metadata_json,
                    decision_id, decision_metadata_json, approver_identity_json,
                    revoked_at, revocation_id, revoked_by_json, revocation_reason,
                    revocation_metadata_json, consumed_at, consumed_by, version
                ) VALUES(
                    ?, ?, ?, NULL, NULL, ?, ?, NULL, NULL, NULL,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1
                )
                """,
                (
                    request.approval_id,
                    request.task_id,
                    request.target_hash,
                    request.reason,
                    _iso(request.created_at),
                    request.target_id,
                    request.target_hash,
                    request.request_hash,
                    request.required_scope,
                    request.risk_level.value,
                    request.reason,
                    _iso(request.expires_at),
                    int(request.one_time_use),
                    self.codec.dumps(dict(request.metadata)),
                ),
            )
            connection.execute(
                """
                UPDATE tasks SET version = version + 1, updated_at = ?
                WHERE task_id = ?
                """,
                (_iso(request.created_at), request.task_id),
            )
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (request.approval_id,),
            ).fetchone()
            assert row is not None
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.APPROVAL_REQUESTED,
                occurred_at=request.created_at,
                name="approval.requested",
                details={
                    "approval_id": request.approval_id,
                    "target_id": request.target_id,
                    "target_hash": request.target_hash,
                    "request_hash": request.request_hash,
                    "required_scope": request.required_scope,
                    "risk_level": request.risk_level,
                    "expires_at": request.expires_at,
                    "one_time_use": request.one_time_use,
                },
                dedupe_key=f"approval:{request.approval_id}:requested",
            )
            return self._stored_approval(row), event

    def record_approval_decision(
        self,
        decision: ApprovalDecision,
    ) -> tuple[StoredApproval, LifecycleEvent | None]:
        """Record one immutable decision after validating its exact request hash."""

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (decision.approval_id,),
            ).fetchone()
            if row is None:
                raise TaskNotFoundError(
                    f"approval {decision.approval_id!r} does not exist"
                )
            stored = self._stored_approval(row)
            if stored.request.request_hash != decision.request_hash:
                raise InvalidTransitionError(
                    "approval decision request hash does not match"
                )
            if decision.decided_at < stored.request.created_at:
                raise InvalidTransitionError(
                    "approval decision cannot predate its request"
                )
            if decision.decided_at >= stored.request.expires_at:
                raise InvalidTransitionError("cannot decide an expired approval")
            if stored.revocation is not None:
                raise InvalidTransitionError("cannot decide a revoked approval")
            if stored.consumed_at is not None:
                raise InvalidTransitionError("cannot decide a consumed approval")
            if stored.decision is not None:
                if stored.decision == decision:
                    return stored, None
                raise ConcurrentUpdateError("approval already has a decision")
            duplicate_decision = connection.execute(
                "SELECT approval_id FROM approvals WHERE decision_id = ?",
                (decision.decision_id,),
            ).fetchone()
            if duplicate_decision is not None:
                raise ConcurrentUpdateError(
                    "approval decision ID belongs to another request"
                )
            task = self._task_row(connection, stored.request.task_id)
            connection.execute(
                """
                UPDATE approvals SET
                    approved = ?, approved_by = ?, reason = ?, decided_at = ?,
                    decision_id = ?, decision_metadata_json = ?,
                    approver_identity_json = ?, version = version + 1
                WHERE approval_id = ? AND version = ?
                """,
                (
                    int(decision.approved),
                    decision.approver.subject,
                    decision.reason,
                    _iso(decision.decided_at),
                    decision.decision_id,
                    self.codec.dumps(dict(decision.metadata)),
                    self.codec.dumps(_approver_identity_dict(decision.approver)),
                    decision.approval_id,
                    stored.version,
                ),
            )
            connection.execute(
                """
                UPDATE tasks SET version = version + 1, updated_at = ?
                WHERE task_id = ?
                """,
                (_iso(decision.decided_at), stored.request.task_id),
            )
            updated = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (decision.approval_id,),
            ).fetchone()
            assert updated is not None
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.APPROVAL_RECEIVED,
                occurred_at=decision.decided_at,
                name="approval.received",
                details={
                    "approval_id": decision.approval_id,
                    "decision_id": decision.decision_id,
                    "request_hash": decision.request_hash,
                    "approved": decision.approved,
                    "approver_subject": decision.approver.subject,
                    "approver_issuer": decision.approver.issuer,
                },
                dedupe_key=f"approval:{decision.approval_id}:decision",
            )
            return self._stored_approval(updated), event

    def revoke_approval(
        self,
        revocation: ApprovalRevocation,
    ) -> tuple[StoredApproval, LifecycleEvent | None]:
        """Revoke an unconsumed approval grant transactionally."""

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (revocation.approval_id,),
            ).fetchone()
            if row is None:
                raise TaskNotFoundError(
                    f"approval {revocation.approval_id!r} does not exist"
                )
            stored = self._stored_approval(row)
            if stored.request.request_hash != revocation.request_hash:
                raise InvalidTransitionError(
                    "approval revocation request hash does not match"
                )
            if revocation.revoked_at < stored.request.created_at:
                raise InvalidTransitionError(
                    "approval revocation cannot predate its request"
                )
            if stored.consumed_at is not None:
                raise InvalidTransitionError("cannot revoke a consumed approval")
            if stored.revocation is not None:
                if stored.revocation == revocation:
                    return stored, None
                raise ConcurrentUpdateError("approval is already revoked")
            duplicate_revocation = connection.execute(
                "SELECT approval_id FROM approvals WHERE revocation_id = ?",
                (revocation.revocation_id,),
            ).fetchone()
            if duplicate_revocation is not None:
                raise ConcurrentUpdateError(
                    "approval revocation ID belongs to another request"
                )
            task = self._task_row(connection, stored.request.task_id)
            connection.execute(
                """
                UPDATE approvals SET revoked_at = ?, revocation_id = ?,
                    revoked_by_json = ?, revocation_reason = ?,
                    revocation_metadata_json = ?, version = version + 1
                WHERE approval_id = ? AND version = ?
                """,
                (
                    _iso(revocation.revoked_at),
                    revocation.revocation_id,
                    self.codec.dumps(_approver_identity_dict(revocation.revoked_by)),
                    revocation.reason,
                    self.codec.dumps(dict(revocation.metadata)),
                    revocation.approval_id,
                    stored.version,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (revocation.approval_id,),
            ).fetchone()
            assert updated is not None
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.APPROVAL_REVOKED,
                occurred_at=revocation.revoked_at,
                name="approval.revoked",
                details={
                    "approval_id": revocation.approval_id,
                    "revocation_id": revocation.revocation_id,
                    "request_hash": revocation.request_hash,
                    "revoked_by": revocation.revoked_by.subject,
                },
                dedupe_key=f"approval:{revocation.approval_id}:revocation",
            )
            return self._stored_approval(updated), event

    def load_approval(self, approval_id: str) -> StoredApproval:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"approval {approval_id!r} does not exist")
        return self._stored_approval(row)

    def find_approval(
        self,
        task_id: str,
        *,
        target_hash: str,
        required_scope: str,
        occurred_at: datetime,
    ) -> StoredApproval | None:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM approvals
                WHERE task_id = ? AND target_hash = ? AND required_scope = ?
                ORDER BY created_at DESC, approval_id DESC
                """,
                (task_id, target_hash, required_scope),
            ).fetchall()
        for row in rows:
            stored = self._stored_approval(row)
            if stored.authorizes(
                request_hash=stored.request.request_hash,
                scope=required_scope,
                now=occurred_at,
            ):
                return stored
        return None

    def consume_approval(
        self,
        approval_id: str,
        *,
        request_hash: str,
        required_scope: str,
        consumed_by: str,
        occurred_at: datetime,
    ) -> StoredApproval:
        """Consume a one-time approval at an explicit execution boundary."""

        require_non_empty(consumed_by, "approval consumer")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise TaskNotFoundError(f"approval {approval_id!r} does not exist")
            stored = self._stored_approval(row)
            if not stored.authorizes(
                request_hash=request_hash,
                scope=required_scope,
                now=occurred_at,
            ):
                if (
                    stored.request.one_time_use
                    and stored.consumed_by == consumed_by
                    and stored.request.request_hash == request_hash
                    and stored.request.required_scope == required_scope
                ):
                    return stored
                raise InvalidTransitionError(
                    "approval is not an active grant for this exact request and scope"
                )
            if not stored.request.one_time_use:
                return stored
            task = self._task_row(connection, stored.request.task_id)
            cursor = connection.execute(
                """
                UPDATE approvals SET consumed_at = ?, consumed_by = ?,
                    version = version + 1
                WHERE approval_id = ? AND version = ? AND consumed_at IS NULL
                """,
                (
                    _iso(occurred_at),
                    consumed_by,
                    approval_id,
                    stored.version,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentUpdateError("approval was consumed concurrently")
            updated = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            assert updated is not None
            self._insert_approval_consumed_event(
                connection,
                task,
                approval_id=approval_id,
                request_hash=request_hash,
                required_scope=required_scope,
                consumed_by=consumed_by,
                occurred_at=occurred_at,
            )
            return self._stored_approval(updated)

    def save_runtime_confirmation(
        self,
        task_id: str,
        confirmation: RuntimeConfirmation,
    ) -> LifecycleEvent | None:
        encoded = self.codec.dumps(_runtime_confirmation_dict(confirmation))
        with self._transaction() as connection:
            task = self._task_row(connection, task_id)
            if self._status(task["current_state"]) is TaskStatus.VERIFIED:
                raise InvalidTransitionError(
                    "cannot add runtime confirmation after task verification"
                )
            existing = connection.execute(
                """
                SELECT task_id, payload_json FROM runtime_confirmations
                WHERE confirmation_id = ?
                """,
                (confirmation.confirmation_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["task_id"]) != task_id
                    or str(existing["payload_json"]) != encoded
                ):
                    raise ConcurrentUpdateError(
                        "runtime confirmation ID has conflicting content"
                    )
                return None
            connection.execute(
                """
                INSERT INTO runtime_confirmations(
                    confirmation_id, task_id, confirmation_key,
                    payload_json, confirmed_at
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (
                    confirmation.confirmation_id,
                    task_id,
                    confirmation.action_id,
                    encoded,
                    _iso(confirmation.confirmed_at),
                ),
            )
            connection.execute(
                """
                UPDATE tasks SET version = version + 1,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (_iso(confirmation.confirmed_at), task_id),
            )
            return self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.RUNTIME_CONFIRMATION_RECEIVED,
                occurred_at=confirmation.confirmed_at,
                name="runtime.confirmation_received",
                details=_runtime_confirmation_dict(confirmation),
                dedupe_key=f"runtime-confirmation:{confirmation.confirmation_id}",
            )

    def runtime_confirmation_values(self, task_id: str) -> dict[str, bool]:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT confirmation_key, payload_json FROM runtime_confirmations
                WHERE task_id = ? ORDER BY confirmed_at, confirmation_id
                """,
                (task_id,),
            ).fetchall()
        result: dict[str, bool] = {}
        try:
            for row in rows:
                payload = self.codec.loads(str(row["payload_json"]))
                if not isinstance(payload, Mapping):
                    raise CorruptStoreError("runtime confirmation payload is invalid")
                result[str(row["confirmation_key"])] = bool(
                    payload.get("supported") and payload.get("safe")
                )
        except (SerializationError, TypeError, ValueError) as error:
            raise CorruptStoreError(
                "persisted runtime confirmation is invalid"
            ) from error
        return result

    def runtime_confirmations(
        self,
        task_id: str,
    ) -> tuple[RuntimeConfirmation, ...]:
        self.load_task(task_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM runtime_confirmations
                WHERE task_id = ? ORDER BY confirmed_at, confirmation_id
                """,
                (task_id,),
            ).fetchall()
        try:
            return tuple(
                _runtime_confirmation(self.codec.loads(str(row["payload_json"])))
                for row in rows
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            if isinstance(error, CorruptStoreError):
                raise
            raise CorruptStoreError(
                "persisted runtime confirmation is invalid"
            ) from error

    def prepare_action(
        self,
        request: ActionRequest,
        *,
        dry_run: bool,
        occurred_at: datetime,
    ) -> tuple[StoredAction, bool, LifecycleEvent | None]:
        encoded_input = self.codec.dumps(dict(request.input))
        with self._transaction() as connection:
            task = self._task_row(connection, request.task_id)
            by_id = connection.execute(
                "SELECT * FROM actions WHERE action_id = ?",
                (request.action_id,),
            ).fetchone()
            by_key = connection.execute(
                """
                SELECT * FROM actions
                WHERE task_id = ? AND required_capability = ?
                    AND idempotency_key = ? AND dry_run = ?
                """,
                (
                    request.task_id,
                    request.required_capability,
                    request.idempotency_key,
                    int(dry_run),
                ),
            ).fetchone()
            if by_id is not None and by_key is not None:
                if str(by_id["action_id"]) != str(by_key["action_id"]):
                    raise ConcurrentUpdateError(
                        "action ID and idempotency key identify different actions"
                    )
            existing = by_id if by_id is not None else by_key
            if existing is not None:
                if (
                    str(existing["task_id"]) != request.task_id
                    or str(existing["action_hash"]) != request.action_hash
                    or bool(existing["dry_run"]) is not dry_run
                ):
                    raise ConcurrentUpdateError(
                        "action identity conflicts with persisted content"
                    )
                return self._stored_action(existing), False, None
            connection.execute(
                """
                INSERT INTO actions(
                    action_id, task_id, name, required_capability, input_json,
                    input_hash, action_hash, idempotency_key, risk_level,
                    requested_by, requested_at, timeout_seconds, dry_run,
                    status, version, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    request.action_id,
                    request.task_id,
                    request.name,
                    request.required_capability,
                    encoded_input,
                    request.input_hash,
                    request.action_hash,
                    request.idempotency_key,
                    request.risk_level.value,
                    request.requested_by,
                    _iso(request.requested_at),
                    request.timeout.total_seconds(),
                    int(dry_run),
                    ActionExecutionStatus.REQUESTED.value,
                    _iso(occurred_at),
                    _iso(occurred_at),
                ),
            )
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.ACTION_REQUESTED,
                occurred_at=occurred_at,
                name="action.requested",
                details={
                    "action_id": request.action_id,
                    "action_name": request.name,
                    "required_capability": request.required_capability,
                    "action_hash": request.action_hash,
                    "input_hash": request.input_hash,
                    "idempotency_key": request.idempotency_key,
                    "risk_level": request.risk_level,
                    "dry_run": dry_run,
                    "claim_source": request.requested_by,
                },
                dedupe_key=f"action:{request.action_id}:requested",
            )
            row = self._action_row(connection, request.action_id)
            return self._stored_action(row), True, event

    def load_action(self, action_id: str) -> StoredAction:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"durable action {action_id!r} does not exist")
        return self._stored_action(row)

    def record_action_policy(
        self,
        action_id: str,
        *,
        expected_version: int,
        decision: ActionPolicyDecision,
    ) -> tuple[StoredAction, LifecycleEvent]:
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_version(action, expected_version)
            self._require_action_status(
                action,
                {ActionExecutionStatus.REQUESTED},
                "record an action policy decision",
            )
            task = self._task_row(connection, str(action["task_id"]))
            connection.execute(
                """
                UPDATE actions SET status = ?, policy_json = ?,
                    policy_task_context_version = ?, version = version + 1,
                    updated_at = ? WHERE action_id = ? AND version = ?
                """,
                (
                    ActionExecutionStatus.POLICY_DECIDED.value,
                    self.codec.dumps(_action_policy_dict(decision)),
                    int(task["execution_context_version"]),
                    _iso(decision.decided_at),
                    action_id,
                    expected_version,
                ),
            )
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.ACTION_POLICY_DECIDED,
                occurred_at=decision.decided_at,
                name="action.policy_decided",
                details={
                    "action_id": action_id,
                    "allowed": decision.allowed,
                    "reasons": decision.reasons,
                    "requires_approval": decision.requires_approval,
                    "decided_by": decision.decided_by,
                },
                dedupe_key=f"action:{action_id}:policy",
            )
            return self._stored_action(self._action_row(connection, action_id)), event

    def record_action_authorization(
        self,
        action_id: str,
        *,
        expected_version: int,
        authorization: PreActionAuthorization,
    ) -> tuple[StoredAction, LifecycleEvent]:
        final_status = (
            ActionExecutionStatus.AUTHORIZED
            if authorization.authorized
            else (
                ActionExecutionStatus.AWAITING_APPROVAL
                if authorization.awaiting_approval
                else ActionExecutionStatus.BLOCKED
            )
        )
        event_type = (
            LifecycleEventType.ACTION_AUTHORIZED
            if authorization.authorized
            else (
                LifecycleEventType.ACTION_AWAITING_APPROVAL
                if authorization.awaiting_approval
                else LifecycleEventType.ACTION_BLOCKED
            )
        )
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_version(action, expected_version)
            self._require_action_status(
                action,
                {
                    ActionExecutionStatus.POLICY_DECIDED,
                    ActionExecutionStatus.AWAITING_APPROVAL,
                },
                "record pre-action authorization",
            )
            connection.execute(
                """
                UPDATE actions SET status = ?, authorization_json = ?,
                    version = version + 1, updated_at = ?
                WHERE action_id = ? AND version = ?
                """,
                (
                    final_status.value,
                    self.codec.dumps(_action_authorization_dict(authorization)),
                    _iso(authorization.authorized_at),
                    action_id,
                    expected_version,
                ),
            )
            task = self._task_row(connection, str(action["task_id"]))
            event = self._insert_task_event(
                connection,
                task,
                event_type=event_type,
                occurred_at=authorization.authorized_at,
                name=event_type.value,
                details={
                    "action_id": action_id,
                    "authorized": authorization.authorized,
                    "reason": authorization.reason,
                    "preconditions": [
                        {
                            "name": item.name,
                            "passed": item.passed,
                            "message": item.message,
                        }
                        for item in authorization.evaluated_preconditions
                    ],
                    "approved_by": authorization.approved_by,
                    "awaiting_approval": authorization.awaiting_approval,
                },
                dedupe_key=f"action:{action_id}:authorization:{expected_version}",
            )
            return self._stored_action(self._action_row(connection, action_id)), event

    def mark_action_executing(
        self,
        action_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
        owner_id: str,
        approval_id: str | None = None,
        approval_request_hash: str | None = None,
        approval_scope: str | None = None,
    ) -> tuple[StoredAction, LifecycleEvent]:
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_version(action, expected_version)
            self._require_action_status(
                action,
                {ActionExecutionStatus.AUTHORIZED},
                "start action execution",
            )
            task = self._task_row(connection, str(action["task_id"]))
            bound_context_version = action["policy_task_context_version"]
            if bound_context_version is None or int(
                task["execution_context_version"]
            ) != int(bound_context_version):
                raise InvalidTransitionError(
                    "action authority is stale for the current task context"
                )
            approval_fields = (
                approval_id,
                approval_request_hash,
                approval_scope,
            )
            if any(item is not None for item in approval_fields) and not all(
                item is not None for item in approval_fields
            ):
                raise ValueError("action approval claim requires all binding fields")
            if approval_id is not None:
                approval_row = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                if approval_row is None:
                    raise InvalidTransitionError("required action approval is missing")
                approval = self._stored_approval(approval_row)
                assert approval_request_hash is not None
                assert approval_scope is not None
                if not approval.authorizes(
                    request_hash=approval_request_hash,
                    scope=approval_scope,
                    now=occurred_at,
                ):
                    raise InvalidTransitionError(
                        "action approval is expired, revoked, consumed, or mismatched"
                    )
                if approval.request.one_time_use:
                    connection.execute(
                        """
                        UPDATE approvals SET consumed_at = ?, consumed_by = ?,
                            version = version + 1
                        WHERE approval_id = ? AND version = ?
                            AND consumed_at IS NULL
                        """,
                        (
                            _iso(occurred_at),
                            f"action:{action_id}",
                            approval_id,
                            approval.version,
                        ),
                    )
                    self._insert_approval_consumed_event(
                        connection,
                        task,
                        approval_id=approval_id,
                        request_hash=approval_request_hash,
                        required_scope=approval_scope,
                        consumed_by=f"action:{action_id}",
                        occurred_at=occurred_at,
                    )
            connection.execute(
                """
                UPDATE actions SET status = ?, version = version + 1,
                    updated_at = ?, started_at = ?, execution_owner_id = ?
                WHERE action_id = ? AND version = ?
                """,
                (
                    ActionExecutionStatus.EXECUTING.value,
                    _iso(occurred_at),
                    _iso(occurred_at),
                    owner_id,
                    action_id,
                    expected_version,
                ),
            )
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.ACTION_EXECUTION_STARTED,
                occurred_at=occurred_at,
                name="action.execution_started",
                details={
                    "action_id": action_id,
                    "action_hash": str(action["action_hash"]),
                    "required_capability": str(action["required_capability"]),
                    "execution_owner_id": owner_id,
                },
                dedupe_key=f"action:{action_id}:execution-started",
            )
            return self._stored_action(self._action_row(connection, action_id)), event

    def finish_action(
        self,
        action_id: str,
        *,
        expected_version: int,
        receipt: ActionReceipt,
    ) -> tuple[StoredAction, LifecycleEvent]:
        event_type = _action_finish_event(receipt.status)
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_version(action, expected_version)
            allowed_current = (
                {ActionExecutionStatus.AUTHORIZED}
                if receipt.status
                in {ActionExecutionStatus.CANCELLED, ActionExecutionStatus.DRY_RUN}
                else {ActionExecutionStatus.EXECUTING}
            )
            self._require_action_status(
                action,
                allowed_current,
                "finish action execution",
            )
            if (
                receipt.action_id != action_id
                or receipt.action_hash != str(action["action_hash"])
                or receipt.input_hash != str(action["input_hash"])
                or receipt.idempotency_key != str(action["idempotency_key"])
            ):
                raise ConcurrentUpdateError(
                    "action receipt does not match the persisted request"
                )
            connection.execute(
                """
                UPDATE actions SET status = ?, receipt_json = ?,
                    postcondition_status = ?, version = version + 1,
                    updated_at = ?, finished_at = ?
                WHERE action_id = ? AND version = ?
                """,
                (
                    receipt.status.value,
                    self.codec.dumps(_action_receipt_dict(receipt)),
                    (
                        ActionPostconditionStatus.PENDING.value
                        if receipt.status is ActionExecutionStatus.EXECUTOR_SUCCEEDED
                        else ActionPostconditionStatus.NOT_STARTED.value
                    ),
                    _iso(receipt.finished_at),
                    _iso(receipt.finished_at),
                    action_id,
                    expected_version,
                ),
            )
            task = self._task_row(connection, str(action["task_id"]))
            event = self._insert_task_event(
                connection,
                task,
                event_type=event_type,
                occurred_at=receipt.finished_at,
                name=event_type.value,
                details={
                    "action_id": action_id,
                    "receipt_id": receipt.receipt_id,
                    "executor_id": receipt.executor_id,
                    "execution_status": receipt.status,
                    "output_hash": receipt.output_hash,
                    "error_type": receipt.error_type,
                },
                dedupe_key=f"action:{action_id}:finished",
            )
            return self._stored_action(self._action_row(connection, action_id)), event

    def complete_action_postconditions(
        self,
        action_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
    ) -> tuple[StoredAction, LifecycleEvent]:
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_version(action, expected_version)
            self._require_action_status(
                action,
                {ActionExecutionStatus.EXECUTOR_SUCCEEDED},
                "complete action postconditions",
            )
            if ActionPostconditionStatus(str(action["postcondition_status"])) is not (
                ActionPostconditionStatus.PENDING
            ):
                raise InvalidTransitionError(
                    "action postconditions are not pending completion"
                )
            connection.execute(
                """
                UPDATE actions SET postcondition_status = ?, version = version + 1,
                    updated_at = ?
                WHERE action_id = ? AND version = ?
                """,
                (
                    ActionPostconditionStatus.COMPLETED.value,
                    _iso(occurred_at),
                    action_id,
                    expected_version,
                ),
            )
            task = self._task_row(connection, str(action["task_id"]))
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.ACTION_POSTCONDITIONS_COMPLETED,
                occurred_at=occurred_at,
                name="action.postconditions_completed",
                details={"action_id": action_id},
                dedupe_key=f"action:{action_id}:postconditions-completed",
            )
            return self._stored_action(self._action_row(connection, action_id)), event

    def mark_action_unknown(
        self,
        action_id: str,
        *,
        expected_version: int,
        occurred_at: datetime,
        reason: str,
    ) -> tuple[StoredAction, LifecycleEvent]:
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_version(action, expected_version)
            self._require_action_status(
                action,
                {ActionExecutionStatus.EXECUTING},
                "mark interrupted action unknown",
            )
            connection.execute(
                """
                UPDATE actions SET status = ?, version = version + 1,
                    updated_at = ?, finished_at = ?
                WHERE action_id = ? AND version = ?
                """,
                (
                    ActionExecutionStatus.UNKNOWN.value,
                    _iso(occurred_at),
                    _iso(occurred_at),
                    action_id,
                    expected_version,
                ),
            )
            task = self._task_row(connection, str(action["task_id"]))
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.ACTION_EXECUTION_UNKNOWN,
                occurred_at=occurred_at,
                name="action.execution_unknown",
                details={"action_id": action_id, "reason": reason},
                dedupe_key=f"action:{action_id}:finished",
            )
            return self._stored_action(self._action_row(connection, action_id)), event

    def complete_action_postcondition(
        self,
        action_id: str,
        *,
        postcondition_name: str,
        items: Sequence[EvidenceItem],
        occurred_at: datetime,
    ) -> tuple[LifecycleEvent, ...]:
        """Atomically persist one complete provider result and its marker."""

        require_non_empty(postcondition_name, "postcondition_name")
        evidence = EvidenceCollection(tuple(items))
        encoded_items = tuple(
            (item, self.codec.dumps(_evidence_dict(item))) for item in evidence
        )
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            self._require_action_status(
                action,
                {ActionExecutionStatus.EXECUTOR_SUCCEEDED},
                "complete an action postcondition",
            )
            if ActionPostconditionStatus(str(action["postcondition_status"])) is not (
                ActionPostconditionStatus.PENDING
            ):
                raise InvalidTransitionError("action postconditions are not pending")
            existing_marker = connection.execute(
                """
                SELECT evidence_count FROM action_postconditions
                WHERE action_id = ? AND postcondition_name = ?
                """,
                (action_id, postcondition_name),
            ).fetchone()
            if existing_marker is not None:
                if int(existing_marker["evidence_count"]) != len(evidence):
                    raise ConcurrentUpdateError(
                        "completed postcondition has conflicting evidence count"
                    )
                return ()

            task_id = str(action["task_id"])
            task = self._task_row(connection, task_id)
            task_status = self._status(task["current_state"])
            if task_status in {TaskStatus.VERIFIED, TaskStatus.FAILED}:
                raise InvalidTransitionError(
                    f"cannot add evidence after task became {task_status.value}"
                )

            events: list[LifecycleEvent] = []
            inserted_evidence = 0
            for item, encoded in encoded_items:
                existing_evidence = connection.execute(
                    """
                    SELECT item_json FROM evidence
                    WHERE task_id = ? AND evidence_id = ?
                    """,
                    (task_id, item.evidence_id),
                ).fetchone()
                if existing_evidence is not None:
                    if str(existing_evidence["item_json"]) != encoded:
                        raise ConcurrentUpdateError(
                            f"evidence ID {item.evidence_id!r} has conflicting content"
                        )
                else:
                    inserted_evidence += 1
                    events.append(
                        self._insert_evidence(connection, task, item, encoded)
                    )

                existing_link = connection.execute(
                    """
                    SELECT postcondition_name FROM action_evidence
                    WHERE action_id = ? AND evidence_id = ?
                    """,
                    (action_id, item.evidence_id),
                ).fetchone()
                if existing_link is not None:
                    if str(existing_link["postcondition_name"]) != postcondition_name:
                        raise ConcurrentUpdateError(
                            "action evidence link conflicts with persisted content"
                        )
                else:
                    connection.execute(
                        """
                        INSERT INTO action_evidence(
                            action_id, task_id, evidence_id,
                            postcondition_name, linked_at
                        ) VALUES(?, ?, ?, ?, ?)
                        """,
                        (
                            action_id,
                            task_id,
                            item.evidence_id,
                            postcondition_name,
                            _iso(occurred_at),
                        ),
                    )
                    events.append(
                        self._insert_task_event(
                            connection,
                            task,
                            event_type=(
                                LifecycleEventType.ACTION_POSTCONDITION_EVIDENCE
                            ),
                            occurred_at=occurred_at,
                            state=task_status,
                            name="action.postcondition_evidence",
                            details={
                                "action_id": action_id,
                                "evidence_id": item.evidence_id,
                                "postcondition": postcondition_name,
                            },
                            dedupe_key=(
                                f"action:{action_id}:evidence:{item.evidence_id}"
                            ),
                        )
                    )

            connection.execute(
                """
                INSERT INTO action_postconditions(
                    action_id, postcondition_name, evidence_count, completed_at
                ) VALUES(?, ?, ?, ?)
                """,
                (action_id, postcondition_name, len(evidence), _iso(occurred_at)),
            )
            if inserted_evidence:
                connection.execute(
                    """
                    UPDATE tasks SET version = version + 1,
                        execution_context_version = execution_context_version + 1,
                        updated_at = ? WHERE task_id = ?
                    """,
                    (_iso(occurred_at), task_id),
                )
            return tuple(events)

    def link_action_evidence(
        self,
        action_id: str,
        evidence_id: str,
        *,
        postcondition_name: str,
        occurred_at: datetime,
    ) -> LifecycleEvent:
        with self._transaction() as connection:
            action = self._action_row(connection, action_id)
            task_id = str(action["task_id"])
            evidence = connection.execute(
                """
                SELECT evidence_id FROM evidence
                WHERE task_id = ? AND evidence_id = ?
                """,
                (task_id, evidence_id),
            ).fetchone()
            if evidence is None:
                raise TaskNotFoundError("action evidence does not exist on its task")
            try:
                connection.execute(
                    """
                    INSERT INTO action_evidence(
                        action_id, task_id, evidence_id, postcondition_name, linked_at
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        task_id,
                        evidence_id,
                        postcondition_name,
                        _iso(occurred_at),
                    ),
                )
            except sqlite3.IntegrityError as error:
                existing = connection.execute(
                    """
                    SELECT postcondition_name FROM action_evidence
                    WHERE action_id = ? AND evidence_id = ?
                    """,
                    (action_id, evidence_id),
                ).fetchone()
                if (
                    existing is None
                    or str(existing["postcondition_name"]) != postcondition_name
                ):
                    raise ConcurrentUpdateError(
                        "action evidence link conflicts with persisted content"
                    ) from error
                prior = self._event_by_dedupe(
                    connection,
                    task_id,
                    f"action:{action_id}:evidence:{evidence_id}",
                )
                if prior is None:
                    raise CorruptStoreError(
                        "action evidence link is missing its event"
                    ) from error
                return self._event(prior)
            task = self._task_row(connection, task_id)
            return self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.ACTION_POSTCONDITION_EVIDENCE,
                occurred_at=occurred_at,
                name="action.postcondition_evidence",
                details={
                    "action_id": action_id,
                    "evidence_id": evidence_id,
                    "postcondition": postcondition_name,
                },
                dedupe_key=f"action:{action_id}:evidence:{evidence_id}",
            )

    def action_evidence(self, action_id: str) -> EvidenceCollection:
        action = self.load_action(action_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evidence.item_json FROM action_evidence
                JOIN evidence
                  ON evidence.task_id = action_evidence.task_id
                 AND evidence.evidence_id = action_evidence.evidence_id
                WHERE action_evidence.action_id = ?
                ORDER BY action_evidence.linked_at, action_evidence.evidence_id
                """,
                (action.action_id,),
            ).fetchall()
        try:
            return EvidenceCollection(
                tuple(self._evidence(str(row["item_json"])) for row in rows)
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            raise CorruptStoreError("persisted action evidence is invalid") from error

    def completed_action_postconditions(self, action_id: str) -> frozenset[str]:
        action = self.load_action(action_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT postcondition_name FROM action_postconditions
                WHERE action_id = ? ORDER BY postcondition_name
                """,
                (action.action_id,),
            ).fetchall()
        return frozenset(str(row["postcondition_name"]) for row in rows)

    def save_recovery_state(
        self,
        plan: RecoveryPlan,
        *,
        status: str,
        occurred_at: datetime,
        expected_version: int | None = None,
    ) -> RecoveryStateRecord:
        try:
            next_status = RecoveryStatus(status)
        except ValueError as error:
            raise InvalidTransitionError(
                f"invalid durable recovery status {status!r}"
            ) from error
        payload = self.codec.dumps(_recovery_plan_dict(plan))
        with self._transaction() as connection:
            self._task_row(connection, plan.task_id)
            row = connection.execute(
                "SELECT * FROM recovery_state WHERE plan_id = ?",
                (plan.plan_id,),
            ).fetchone()
            if row is None:
                if expected_version not in {None, 0}:
                    raise ConcurrentUpdateError("recovery plan does not exist")
                if next_status not in _DURABLE_RECOVERY_TRANSITIONS[None]:
                    raise InvalidTransitionError(
                        "new durable recovery plans must start as planned"
                    )
                version = 1
                connection.execute(
                    """
                    INSERT INTO recovery_state(
                        plan_id, task_id, status, payload_json, version, updated_at,
                        plan_hash
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.task_id,
                        next_status.value,
                        payload,
                        version,
                        _iso(occurred_at),
                        plan.plan_hash,
                    ),
                )
            else:
                if str(row["task_id"]) != plan.task_id:
                    raise ConcurrentUpdateError(
                        "recovery plan ID belongs to a different task"
                    )
                if (
                    row["plan_hash"] is not None
                    and str(row["plan_hash"]) != plan.plan_hash
                ):
                    raise ConcurrentUpdateError(
                        "recovery plan ID has conflicting immutable content"
                    )
                current_version = int(row["version"])
                if expected_version != current_version:
                    raise ConcurrentUpdateError("recovery state changed concurrently")
                try:
                    current_status = RecoveryStatus(str(row["status"]))
                except ValueError as error:
                    raise CorruptStoreError(
                        f"invalid persisted recovery status {row['status']!r}"
                    ) from error
                if next_status not in _DURABLE_RECOVERY_TRANSITIONS[current_status]:
                    raise InvalidTransitionError(
                        "invalid durable recovery transition from "
                        f"{current_status.value} to {next_status.value}"
                    )
                version = current_version + 1
                connection.execute(
                    """
                    UPDATE recovery_state SET status = ?, payload_json = ?,
                        version = ?, updated_at = ?, plan_hash = ?
                    WHERE plan_id = ? AND version = ?
                    """,
                    (
                        next_status.value,
                        payload,
                        version,
                        _iso(occurred_at),
                        plan.plan_hash,
                        plan.plan_id,
                        current_version,
                    ),
                )
        return RecoveryStateRecord(
            plan_id=plan.plan_id,
            task_id=plan.task_id,
            status=next_status.value,
            payload=_recovery_plan_dict(plan),
            version=version,
            updated_at=occurred_at,
        )

    def save_recovery_approval(
        self,
        task_id: str,
        approval: RecoveryApproval,
        *,
        occurred_at: datetime,
    ) -> ApprovalRecord:
        record, _ = self.decide_approval(
            task_id,
            approval_key=approval.action_id,
            approved=approval.approved,
            approved_by=approval.approved_by,
            reason=approval.reason,
            occurred_at=occurred_at,
            approval_id=f"recovery:{approval.action_id}:{approval.idempotency_key}",
            capability=approval.capability,
            idempotency_key=approval.idempotency_key,
        )
        return record

    def load_recovery_state(self, plan_id: str) -> RecoveryStateRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM recovery_state WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = self.codec.loads(str(row["payload_json"]))
            if not isinstance(payload, Mapping):
                raise CorruptStoreError("recovery payload is not an object")
            if payload.get("plan_id") not in {None, str(row["plan_id"])}:
                raise CorruptStoreError("recovery payload plan ID does not match")
            if payload.get("task_id") not in {None, str(row["task_id"])}:
                raise CorruptStoreError("recovery payload task ID does not match")
            try:
                persisted_status = RecoveryStatus(str(row["status"]))
            except ValueError as error:
                raise CorruptStoreError(
                    f"invalid persisted recovery status {row['status']!r}"
                ) from error
            persisted_plan_hash = _optional_str(row["plan_hash"])
            payload_plan_hash = _optional_str(payload.get("plan_hash"))
            if (
                payload_plan_hash is not None
                and persisted_plan_hash != payload_plan_hash
            ):
                raise CorruptStoreError("recovery plan hash does not match")
            receipt = (
                None
                if row["receipt_json"] is None
                else self.codec.loads(str(row["receipt_json"]))
            )
            if receipt is not None and not isinstance(receipt, Mapping):
                raise CorruptStoreError("recovery receipt is not an object")
            if receipt is not None:
                decoded_receipt = _recovery_receipt(receipt)
                if decoded_receipt.plan_id != str(row["plan_id"]):
                    raise CorruptStoreError("recovery receipt plan ID does not match")
                actions = payload.get("actions")
                if not isinstance(actions, list) or not any(
                    isinstance(action, Mapping)
                    and action.get("action_id") == decoded_receipt.action_id
                    and action.get("action_hash") == decoded_receipt.action_hash
                    for action in actions
                ):
                    raise CorruptStoreError(
                        "recovery receipt action identity does not match"
                    )
            return RecoveryStateRecord(
                plan_id=str(row["plan_id"]),
                task_id=str(row["task_id"]),
                status=persisted_status.value,
                payload=payload,
                version=int(row["version"]),
                updated_at=_datetime(row["updated_at"]),
                execution_owner_id=_optional_str(row["execution_owner_id"]),
                receipt=receipt,
                approval_id=_optional_str(row["approval_id"]),
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            if isinstance(error, CorruptStoreError):
                raise
            raise CorruptStoreError("persisted recovery state is invalid") from error

    def claim_recovery_execution(
        self,
        plan: RecoveryPlan,
        *,
        expected_version: int,
        owner_id: str,
        occurred_at: datetime,
        approval_id: str | None = None,
        approval_request_hash: str | None = None,
        approval_scope: str | None = None,
    ) -> tuple[RecoveryStateRecord, LifecycleEvent]:
        """Atomically consume approval, reserve idempotency, and start recovery."""

        if len(plan.actions) != 1:
            raise InvalidTransitionError(
                "durable recovery executes exactly one action per plan"
            )
        action = plan.actions[0]
        scope = f"recovery:{plan.task_id}:{action.capability}"
        with self._transaction() as connection:
            row = self._recovery_state_row(
                connection, plan.plan_id, expected_version=expected_version
            )
            if str(row["plan_hash"]) != plan.plan_hash:
                raise ConcurrentUpdateError("recovery plan hash does not match")
            if str(row["status"]) != RecoveryStatus.AUTHORIZED.value:
                raise InvalidTransitionError(
                    f"cannot start recovery while state is {row['status']}"
                )
            task = self._task_row(connection, plan.task_id)
            if self._status(task["current_state"]) not in {
                TaskStatus.FAILED,
                TaskStatus.INCONCLUSIVE,
                TaskStatus.AWAITING_EVIDENCE,
                TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
            }:
                raise InvalidTransitionError(
                    "recovery requires an authoritative failed or incomplete task"
                )
            approval_fields = (
                approval_id,
                approval_request_hash,
                approval_scope,
            )
            if any(item is not None for item in approval_fields) and not all(
                item is not None for item in approval_fields
            ):
                raise ValueError("recovery approval claim requires all binding fields")
            if approval_id is not None:
                approval_row = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                if approval_row is None:
                    raise InvalidTransitionError(
                        "required recovery approval is missing"
                    )
                approval = self._stored_approval(approval_row)
                assert approval_request_hash is not None
                assert approval_scope is not None
                if not approval.authorizes(
                    request_hash=approval_request_hash,
                    scope=approval_scope,
                    now=occurred_at,
                ):
                    raise InvalidTransitionError(
                        "recovery approval is expired, revoked, consumed, or mismatched"
                    )
                if approval.request.one_time_use:
                    cursor = connection.execute(
                        """
                        UPDATE approvals SET consumed_at = ?, consumed_by = ?,
                            version = version + 1
                        WHERE approval_id = ? AND version = ?
                            AND consumed_at IS NULL
                        """,
                        (
                            _iso(occurred_at),
                            f"recovery:{plan.plan_id}",
                            approval_id,
                            approval.version,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ConcurrentUpdateError(
                            "recovery approval was consumed concurrently"
                        )
                    self._insert_approval_consumed_event(
                        connection,
                        task,
                        approval_id=approval_id,
                        request_hash=approval_request_hash,
                        required_scope=approval_scope,
                        consumed_by=f"recovery:{plan.plan_id}",
                        occurred_at=occurred_at,
                    )
            try:
                connection.execute(
                    """
                    INSERT INTO idempotency_records(
                        scope, idempotency_key, owner_id, status, result_json,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, 'reserved', NULL, ?, ?)
                    """,
                    (
                        scope,
                        action.idempotency_key,
                        owner_id,
                        _iso(occurred_at),
                        _iso(occurred_at),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ConcurrentUpdateError(
                    "recovery idempotency key is already reserved"
                ) from error
            next_version = expected_version + 1
            connection.execute(
                """
                UPDATE recovery_state SET status = ?, execution_owner_id = ?,
                    approval_id = ?, started_at = ?, updated_at = ?,
                    version = ?
                WHERE plan_id = ? AND version = ?
                """,
                (
                    RecoveryStatus.EXECUTING.value,
                    owner_id,
                    approval_id,
                    _iso(occurred_at),
                    _iso(occurred_at),
                    next_version,
                    plan.plan_id,
                    expected_version,
                ),
            )
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.RECOVERY_EXECUTION_STARTED,
                occurred_at=occurred_at,
                name="recovery.execution_started",
                details={
                    "plan_id": plan.plan_id,
                    "plan_hash": plan.plan_hash,
                    "action_id": action.action_id,
                    "action_hash": action.action_hash,
                    "capability": action.capability,
                    "idempotency_key": action.idempotency_key,
                    "execution_owner_id": owner_id,
                },
                dedupe_key=f"recovery:{plan.plan_id}:execution-started",
            )
        return (
            RecoveryStateRecord(
                plan_id=plan.plan_id,
                task_id=plan.task_id,
                status=RecoveryStatus.EXECUTING.value,
                payload=_recovery_plan_dict(plan),
                version=next_version,
                updated_at=occurred_at,
            ),
            event,
        )

    def finish_recovery_execution(
        self,
        plan: RecoveryPlan,
        *,
        expected_version: int,
        owner_id: str,
        receipt: RecoveryExecutionReceipt,
    ) -> tuple[RecoveryStateRecord, LifecycleEvent]:
        if len(plan.actions) != 1:
            raise InvalidTransitionError("durable recovery requires one action")
        action = plan.actions[0]
        if (
            receipt.plan_id != plan.plan_id
            or receipt.action_id != action.action_id
            or receipt.action_hash != action.action_hash
        ):
            raise InvalidTransitionError("recovery receipt identity does not match")
        encoded_receipt = self.codec.dumps(_recovery_receipt_dict(receipt))
        scope = f"recovery:{plan.task_id}:{action.capability}"
        with self._transaction() as connection:
            row = self._recovery_state_row(
                connection, plan.plan_id, expected_version=expected_version
            )
            if str(row["status"]) != RecoveryStatus.EXECUTING.value:
                raise InvalidTransitionError("recovery execution is not active")
            if str(row["execution_owner_id"]) != owner_id:
                raise ConcurrentUpdateError("recovery execution owner changed")
            if str(row["plan_hash"]) != plan.plan_hash:
                raise ConcurrentUpdateError("recovery plan hash does not match")
            task = self._task_row(connection, plan.task_id)
            next_version = expected_version + 1
            connection.execute(
                """
                UPDATE recovery_state SET status = ?, receipt_json = ?,
                    finished_at = ?, updated_at = ?, version = ?
                WHERE plan_id = ? AND version = ?
                """,
                (
                    receipt.status.value,
                    encoded_receipt,
                    _iso(receipt.finished_at),
                    _iso(receipt.finished_at),
                    next_version,
                    plan.plan_id,
                    expected_version,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE idempotency_records SET status = 'completed',
                    result_json = ?, updated_at = ?
                WHERE scope = ? AND idempotency_key = ? AND owner_id = ?
                    AND status = 'reserved'
                """,
                (
                    encoded_receipt,
                    _iso(receipt.finished_at),
                    scope,
                    action.idempotency_key,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentUpdateError(
                    "recovery idempotency reservation is not active"
                )
            event_type = {
                RecoveryStatus.EXECUTOR_SUCCEEDED: (
                    LifecycleEventType.RECOVERY_EXECUTOR_SUCCEEDED
                ),
                RecoveryStatus.FAILED: LifecycleEventType.RECOVERY_EXECUTION_FAILED,
                RecoveryStatus.UNKNOWN: LifecycleEventType.RECOVERY_EXECUTION_UNKNOWN,
                RecoveryStatus.DRY_RUN: LifecycleEventType.RECOVERY_EXECUTION_FAILED,
            }[receipt.status]
            event = self._insert_task_event(
                connection,
                task,
                event_type=event_type,
                occurred_at=receipt.finished_at,
                name=event_type.value,
                details={
                    "plan_id": plan.plan_id,
                    "action_id": action.action_id,
                    "receipt_id": receipt.receipt_id,
                    "receipt_status": receipt.status,
                    "executor_id": receipt.executor_id,
                    "output_hash": receipt.output_hash,
                    "proves_external_postcondition": False,
                    "proves_verified_outcome": False,
                },
                dedupe_key=f"recovery:{plan.plan_id}:receipt",
            )
        return (
            RecoveryStateRecord(
                plan_id=plan.plan_id,
                task_id=plan.task_id,
                status=receipt.status.value,
                payload=_recovery_plan_dict(plan),
                version=next_version,
                updated_at=receipt.finished_at,
            ),
            event,
        )

    def mark_recovery_unknown(
        self,
        plan: RecoveryPlan,
        *,
        expected_version: int,
        occurred_at: datetime,
        reason: str,
    ) -> tuple[RecoveryStateRecord, LifecycleEvent]:
        if len(plan.actions) != 1:
            raise InvalidTransitionError("durable recovery requires one action")
        action = plan.actions[0]
        scope = f"recovery:{plan.task_id}:{action.capability}"
        with self._transaction() as connection:
            row = self._recovery_state_row(
                connection, plan.plan_id, expected_version=expected_version
            )
            if str(row["status"]) != RecoveryStatus.EXECUTING.value:
                raise InvalidTransitionError("recovery execution is not active")
            task = self._task_row(connection, plan.task_id)
            next_version = expected_version + 1
            connection.execute(
                """
                UPDATE recovery_state SET status = ?, finished_at = ?,
                    updated_at = ?, version = ? WHERE plan_id = ? AND version = ?
                """,
                (
                    RecoveryStatus.UNKNOWN.value,
                    _iso(occurred_at),
                    _iso(occurred_at),
                    next_version,
                    plan.plan_id,
                    expected_version,
                ),
            )
            connection.execute(
                """
                UPDATE idempotency_records SET status = 'completed',
                    result_json = ?, updated_at = ?
                WHERE scope = ? AND idempotency_key = ? AND status = 'reserved'
                """,
                (
                    self.codec.dumps({"status": "unknown", "reason": reason}),
                    _iso(occurred_at),
                    scope,
                    action.idempotency_key,
                ),
            )
            event = self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.RECOVERY_EXECUTION_UNKNOWN,
                occurred_at=occurred_at,
                name="recovery.execution_unknown",
                details={
                    "plan_id": plan.plan_id,
                    "action_id": action.action_id,
                    "reason": reason,
                },
                dedupe_key=f"recovery:{plan.plan_id}:unknown",
            )
        return (
            RecoveryStateRecord(
                plan_id=plan.plan_id,
                task_id=plan.task_id,
                status=RecoveryStatus.UNKNOWN.value,
                payload=_recovery_plan_dict(plan),
                version=next_version,
                updated_at=occurred_at,
            ),
            event,
        )

    def link_recovery_evidence(
        self,
        plan_id: str,
        evidence_id: str,
        *,
        postcondition_name: str,
        occurred_at: datetime,
    ) -> LifecycleEvent:
        with self._transaction() as connection:
            recovery = self._recovery_state_row(connection, plan_id)
            task_id = str(recovery["task_id"])
            evidence = connection.execute(
                """
                SELECT 1 FROM evidence WHERE task_id = ? AND evidence_id = ?
                """,
                (task_id, evidence_id),
            ).fetchone()
            if evidence is None:
                raise TaskNotFoundError("recovery evidence does not exist")
            connection.execute(
                """
                INSERT OR IGNORE INTO recovery_evidence(
                    plan_id, task_id, evidence_id, postcondition_name, linked_at
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (plan_id, task_id, evidence_id, postcondition_name, _iso(occurred_at)),
            )
            task = self._task_row(connection, task_id)
            return self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.RECOVERY_POSTCONDITION_EVIDENCE,
                occurred_at=occurred_at,
                name="recovery.postcondition_evidence",
                details={
                    "plan_id": plan_id,
                    "evidence_id": evidence_id,
                    "postcondition": postcondition_name,
                },
                dedupe_key=f"recovery:{plan_id}:evidence:{evidence_id}",
            )

    def record_recovery_evidence(
        self,
        plan_id: str,
        *,
        postcondition_name: str,
        item: EvidenceItem,
        occurred_at: datetime,
    ) -> tuple[EvidenceItem, tuple[LifecycleEvent, ...]]:
        """Persist and link postcondition evidence in one recovery transaction."""

        encoded = self.codec.dumps(_evidence_dict(item))
        with self._transaction() as connection:
            recovery = self._recovery_state_row(connection, plan_id)
            if str(recovery["status"]) != RecoveryStatus.EXECUTOR_SUCCEEDED.value:
                raise InvalidTransitionError(
                    "recovery evidence requires executor-reported success"
                )
            task_id = str(recovery["task_id"])
            task = self._task_row(connection, task_id)
            if self._status(task["current_state"]) is TaskStatus.VERIFIED:
                raise InvalidTransitionError(
                    "cannot append recovery evidence after verification"
                )
            existing = connection.execute(
                """
                SELECT item_json FROM evidence
                WHERE task_id = ? AND evidence_id = ?
                """,
                (task_id, item.evidence_id),
            ).fetchone()
            if existing is not None and str(existing["item_json"]) != encoded:
                raise ConcurrentUpdateError(
                    "recovery evidence ID has conflicting immutable content"
                )
            events: list[LifecycleEvent] = []
            if existing is None:
                events.append(self._insert_evidence(connection, task, item, encoded))
            link = connection.execute(
                """
                SELECT 1 FROM recovery_evidence
                WHERE plan_id = ? AND evidence_id = ?
                """,
                (plan_id, item.evidence_id),
            ).fetchone()
            if link is None:
                connection.execute(
                    """
                    INSERT INTO recovery_evidence(
                        plan_id, task_id, evidence_id, postcondition_name, linked_at
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        plan_id,
                        task_id,
                        item.evidence_id,
                        postcondition_name,
                        _iso(occurred_at),
                    ),
                )
                events.append(
                    self._insert_task_event(
                        connection,
                        task,
                        event_type=(LifecycleEventType.RECOVERY_POSTCONDITION_EVIDENCE),
                        occurred_at=occurred_at,
                        name="recovery.postcondition_evidence",
                        details={
                            "plan_id": plan_id,
                            "evidence_id": item.evidence_id,
                            "postcondition": postcondition_name,
                        },
                        dedupe_key=f"recovery:{plan_id}:evidence:{item.evidence_id}",
                    )
                )
        return item, tuple(events)

    def recovery_evidence(self, plan_id: str) -> EvidenceCollection:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evidence.item_json FROM recovery_evidence
                JOIN evidence
                  ON evidence.task_id = recovery_evidence.task_id
                 AND evidence.evidence_id = recovery_evidence.evidence_id
                WHERE recovery_evidence.plan_id = ?
                ORDER BY recovery_evidence.linked_at, recovery_evidence.evidence_id
                """,
                (plan_id,),
            ).fetchall()
        return EvidenceCollection(
            tuple(self._evidence(str(row["item_json"])) for row in rows)
        )

    def reserve_idempotency(
        self,
        *,
        scope: str,
        key: str,
        owner_id: str,
        occurred_at: datetime,
    ) -> IdempotencyRecord:
        with self._transaction() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO idempotency_records(
                        scope, idempotency_key, owner_id, status, result_json,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, 'reserved', NULL, ?, ?)
                    """,
                    (scope, key, owner_id, _iso(occurred_at), _iso(occurred_at)),
                )
            except sqlite3.IntegrityError as error:
                raise ConcurrentUpdateError(
                    f"idempotency key {scope}:{key} is already reserved"
                ) from error
        return IdempotencyRecord(
            scope=scope,
            key=key,
            owner_id=owner_id,
            status="reserved",
            result=None,
            created_at=occurred_at,
            updated_at=occurred_at,
        )

    def complete_idempotency(
        self,
        *,
        scope: str,
        key: str,
        owner_id: str,
        result: Any,
        occurred_at: datetime,
    ) -> None:
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE idempotency_records
                SET status = 'completed', result_json = ?, updated_at = ?
                WHERE scope = ? AND idempotency_key = ? AND owner_id = ?
                    AND status = 'reserved'
                """,
                (
                    self.codec.dumps(result),
                    _iso(occurred_at),
                    scope,
                    key,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ConcurrentUpdateError("idempotency reservation is not active")

    def idempotency_record(
        self,
        *,
        scope: str,
        key: str,
    ) -> IdempotencyRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM idempotency_records
                WHERE scope = ? AND idempotency_key = ?
                """,
                (scope, key),
            ).fetchone()
        if row is None:
            return None
        try:
            result = (
                None
                if row["result_json"] is None
                else self.codec.loads(str(row["result_json"]))
            )
            return IdempotencyRecord(
                scope=str(row["scope"]),
                key=str(row["idempotency_key"]),
                owner_id=str(row["owner_id"]),
                status=str(row["status"]),
                result=result,
                created_at=_datetime(row["created_at"]),
                updated_at=_datetime(row["updated_at"]),
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            raise CorruptStoreError(
                "persisted idempotency record is invalid"
            ) from error

    def continuation_token(self, task_id: str, status: TaskStatus) -> str:
        with self._connect() as connection:
            if status is TaskStatus.AWAITING_EVIDENCE:
                row = connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
            elif status is TaskStatus.AWAITING_APPROVAL:
                row = connection.execute(
                    """
                    SELECT COUNT(*), COALESCE(SUM(version), 0) FROM approvals
                    WHERE task_id = ?
                    """,
                    (task_id,),
                ).fetchone()
            elif status is TaskStatus.AWAITING_RUNTIME_CONFIRMATION:
                row = connection.execute(
                    "SELECT COUNT(*) FROM runtime_confirmations WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
            else:
                return ""
        if status is TaskStatus.AWAITING_APPROVAL and row is not None:
            return f"{status.value}:{int(row[0])}:{int(row[1])}"
        return f"{status.value}:{int(row[0]) if row is not None else 0}"

    def _initialize(self, target_version: int) -> None:
        with self._initialization_lock, self._connect() as connection:
            while True:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    current_row = connection.execute("PRAGMA user_version").fetchone()
                    current = int(current_row[0]) if current_row is not None else 0
                    if current > LATEST_SCHEMA_VERSION:
                        raise SchemaVersionError(
                            f"database schema {current} is newer than supported "
                            f"schema {LATEST_SCHEMA_VERSION}"
                        )
                    if current >= target_version:
                        connection.commit()
                        return
                    version = current + 1
                    for statement in _MIGRATIONS[version]:
                        connection.execute(statement)
                    if version == 3:
                        self._migrate_evidence_v3(connection)
                    if version == 4:
                        self._migrate_approvals_and_recovery_v4(connection)
                    if version == 5:
                        self._migrate_evidence_trust_v5(connection)
                    if version == 7:
                        self._migrate_verified_invariant_v7(connection)
                    connection.execute(
                        """
                        INSERT INTO schema_migrations(version, applied_at)
                        VALUES(?, ?)
                        """,
                        (version, datetime.now(UTC).isoformat()),
                    )
                    connection.execute(f"PRAGMA user_version = {version}")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise

    def _migrate_evidence_v3(self, connection: sqlite3.Connection) -> None:
        evidence_rows = connection.execute(
            "SELECT task_id, evidence_id, item_json FROM evidence"
        ).fetchall()
        for row in evidence_rows:
            value = self.codec.loads(str(row["item_json"]))
            if not isinstance(value, Mapping):
                raise CorruptStoreError("legacy evidence is not an object")
            item = dict(value)
            payload = item.get("payload")
            if payload is not None and not isinstance(payload, Mapping):
                raise CorruptStoreError("legacy evidence payload is invalid")
            content = item.get("content")
            if content is not None and not isinstance(content, (str, bytes)):
                raise CorruptStoreError("legacy evidence content is invalid")
            item["checksum"] = calculate_evidence_checksum(content, payload)
            item.setdefault(
                "acquisition_method",
                EvidenceAcquisitionMethod.AGENT_REPORTED.value,
            )
            item.setdefault("trust_level", int(EvidenceTrustLevel.AGENT_CLAIM))
            item.setdefault("expires_at", None)
            connection.execute(
                """
                UPDATE evidence SET item_json = ?
                WHERE task_id = ? AND evidence_id = ?
                """,
                (
                    self.codec.dumps(item),
                    str(row["task_id"]),
                    str(row["evidence_id"]),
                ),
            )

        task_rows = connection.execute(
            "SELECT task_id, contract_json FROM tasks"
        ).fetchall()
        for row in task_rows:
            value = self.codec.loads(str(row["contract_json"]))
            if not isinstance(value, Mapping):
                raise CorruptStoreError("legacy contract is not an object")
            contract = dict(value)
            requirements = contract.get("required_evidence")
            if not isinstance(requirements, list):
                raise CorruptStoreError("legacy evidence requirements are invalid")
            migrated_requirements: list[dict[str, Any]] = []
            for requirement in requirements:
                if not isinstance(requirement, Mapping):
                    raise CorruptStoreError(
                        "legacy evidence requirement is not an object"
                    )
                migrated = dict(requirement)
                migrated.setdefault(
                    "minimum_trust_level",
                    int(EvidenceTrustLevel.AGENT_CLAIM),
                )
                migrated.setdefault("max_age_seconds", None)
                migrated_requirements.append(migrated)
            contract["required_evidence"] = migrated_requirements
            encoded = self.codec.dumps(contract)
            connection.execute(
                """
                UPDATE tasks SET contract_json = ?, contract_digest = ?
                WHERE task_id = ?
                """,
                (
                    encoded,
                    hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                    str(row["task_id"]),
                ),
            )

        connection.execute(
            """
            CREATE TRIGGER evidence_immutable_update
            BEFORE UPDATE ON evidence
            BEGIN
                SELECT RAISE(ABORT, 'persisted evidence is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER evidence_immutable_delete
            BEFORE DELETE ON evidence
            BEGIN
                SELECT RAISE(ABORT, 'persisted evidence is immutable');
            END
            """
        )

    def _migrate_approvals_and_recovery_v4(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Upgrade legacy approvals without silently granting new authority."""

        rows = connection.execute("SELECT * FROM approvals").fetchall()
        far_future = datetime.max.replace(tzinfo=UTC)
        for row in rows:
            created_at = _datetime(row["created_at"])
            request = ApprovalRequest(
                approval_id=str(row["approval_id"]),
                task_id=str(row["task_id"]),
                target_id=str(row["approval_key"]),
                target_hash=str(row["approval_key"]),
                required_scope="legacy.approval",
                risk_level=RiskLevel.LOW,
                reason=str(row["reason"]),
                created_at=created_at,
                expires_at=far_future,
                one_time_use=False,
                metadata={"legacy_schema": 2},
            )
            decision_id: str | None = None
            decision_metadata: str | None = None
            identity_json: str | None = None
            if row["approved"] is not None:
                decision_id = f"legacy-decision:{request.approval_id}"
                decided_at = _datetime(row["decided_at"])
                identity_json = self.codec.dumps(
                    _approver_identity_dict(
                        ApproverIdentity(
                            subject=str(row["approved_by"]),
                            issuer="legacy-unverified",
                            authenticated_at=decided_at,
                            authentication_method="legacy-string",
                            claims={"migrated": True},
                        )
                    )
                )
                decision_metadata = self.codec.dumps({"migrated": True})
            connection.execute(
                """
                UPDATE approvals SET target_id = ?, target_hash = ?,
                    request_hash = ?, required_scope = ?, risk_level = ?,
                    request_reason = ?, expires_at = ?, one_time_use = 0,
                    request_metadata_json = ?, decision_id = ?,
                    decision_metadata_json = ?, approver_identity_json = ?,
                    version = 1
                WHERE approval_id = ?
                """,
                (
                    request.target_id,
                    request.target_hash,
                    request.request_hash,
                    request.required_scope,
                    request.risk_level.value,
                    request.reason,
                    _iso(request.expires_at),
                    self.codec.dumps(dict(request.metadata)),
                    decision_id,
                    decision_metadata,
                    identity_json,
                    request.approval_id,
                ),
            )

        recovery_rows = connection.execute(
            "SELECT plan_id, payload_json FROM recovery_state"
        ).fetchall()
        for row in recovery_rows:
            payload = self.codec.loads(str(row["payload_json"]))
            if not isinstance(payload, Mapping):
                raise CorruptStoreError("legacy recovery plan is not an object")
            plan_hash = (
                "sha256:"
                + hashlib.sha256(self.codec.dumps(payload).encode("utf-8")).hexdigest()
            )
            connection.execute(
                "UPDATE recovery_state SET plan_hash = ? WHERE plan_id = ?",
                (plan_hash, str(row["plan_id"])),
            )
        connection.execute(
            """
            CREATE TRIGGER approval_request_immutable
            BEFORE UPDATE ON approvals
            WHEN OLD.task_id IS NOT NEW.task_id
              OR OLD.target_id IS NOT NEW.target_id
              OR OLD.target_hash IS NOT NEW.target_hash
              OR OLD.request_hash IS NOT NEW.request_hash
              OR OLD.required_scope IS NOT NEW.required_scope
              OR OLD.risk_level IS NOT NEW.risk_level
              OR OLD.request_reason IS NOT NEW.request_reason
              OR OLD.created_at IS NOT NEW.created_at
              OR OLD.expires_at IS NOT NEW.expires_at
              OR OLD.one_time_use IS NOT NEW.one_time_use
              OR OLD.request_metadata_json IS NOT NEW.request_metadata_json
            BEGIN
                SELECT RAISE(ABORT, 'persisted approval request is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER approval_decision_immutable
            BEFORE UPDATE ON approvals
            WHEN OLD.decision_id IS NOT NULL AND (
                 OLD.decision_id IS NOT NEW.decision_id
              OR OLD.approved IS NOT NEW.approved
              OR OLD.approved_by IS NOT NEW.approved_by
              OR OLD.reason IS NOT NEW.reason
              OR OLD.decided_at IS NOT NEW.decided_at
              OR OLD.decision_metadata_json IS NOT NEW.decision_metadata_json
              OR OLD.approver_identity_json IS NOT NEW.approver_identity_json
            )
            BEGIN
                SELECT RAISE(ABORT, 'persisted approval decision is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER approval_revocation_immutable
            BEFORE UPDATE ON approvals
            WHEN OLD.revocation_id IS NOT NULL AND (
                 OLD.revocation_id IS NOT NEW.revocation_id
              OR OLD.revoked_at IS NOT NEW.revoked_at
              OR OLD.revoked_by_json IS NOT NEW.revoked_by_json
              OR OLD.revocation_reason IS NOT NEW.revocation_reason
              OR OLD.revocation_metadata_json IS NOT NEW.revocation_metadata_json
            )
            BEGIN
                SELECT RAISE(ABORT, 'persisted approval revocation is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER approval_consumption_immutable
            BEFORE UPDATE ON approvals
            WHEN OLD.consumed_at IS NOT NULL AND (
                 OLD.consumed_at IS NOT NEW.consumed_at
              OR OLD.consumed_by IS NOT NEW.consumed_by
            )
            BEGIN
                SELECT RAISE(ABORT, 'persisted approval consumption is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER approval_immutable_delete
            BEFORE DELETE ON approvals
            BEGIN
                SELECT RAISE(ABORT, 'persisted approval audit record is immutable');
            END
            """
        )

    def _migrate_evidence_trust_v5(self, connection: sqlite3.Connection) -> None:
        """Conservatively remove unestablished trust from pre-v5 evidence."""

        connection.execute("DROP TRIGGER IF EXISTS evidence_immutable_update")
        connection.execute("DROP TRIGGER IF EXISTS evidence_immutable_delete")
        rows = connection.execute(
            "SELECT task_id, evidence_id, item_json FROM evidence"
        ).fetchall()
        affected_tasks: set[str] = set()
        for row in rows:
            value = self.codec.loads(str(row["item_json"]))
            if not isinstance(value, Mapping):
                raise CorruptStoreError("legacy evidence is not an object")
            item = dict(value)
            item["trust_level"] = int(EvidenceTrustLevel.AGENT_CLAIM)
            item["acquisition_method"] = EvidenceAcquisitionMethod.AGENT_REPORTED.value
            item["trust_origin"] = {}
            item["origin_hash"] = None
            connection.execute(
                """
                UPDATE evidence SET item_json = ?
                WHERE task_id = ? AND evidence_id = ?
                """,
                (
                    self.codec.dumps(item),
                    str(row["task_id"]),
                    str(row["evidence_id"]),
                ),
            )
            affected_tasks.add(str(row["task_id"]))

        for task_id in affected_tasks:
            task = self._task_row(connection, task_id)
            if self._status(task["current_state"]) is not TaskStatus.VERIFIED:
                continue
            contract_value = self.codec.loads(str(task["contract_json"]))
            if not isinstance(contract_value, Mapping):
                raise CorruptStoreError("persisted contract is not an object")
            requirements = contract_value.get("required_evidence", [])
            if not requirements:
                continue
            now = datetime.now(UTC)
            connection.execute(
                """
                UPDATE tasks SET current_state = ?, verification_json = NULL,
                    wait_token = NULL, finished_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE task_id = ?
                """,
                (TaskStatus.INCONCLUSIVE.value, _iso(now), task_id),
            )
            self._insert_task_event(
                connection,
                task,
                event_type=LifecycleEventType.STATE_TRANSITION,
                occurred_at=now,
                state=TaskStatus.INCONCLUSIVE,
                previous_state=TaskStatus.VERIFIED,
                details={"reason": "legacy_evidence_trust_not_established"},
                dedupe_key="migration:v5:evidence-trust-downgrade",
            )

        connection.execute(
            """
            CREATE TRIGGER evidence_immutable_update
            BEFORE UPDATE ON evidence
            BEGIN
                SELECT RAISE(ABORT, 'persisted evidence is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER evidence_immutable_delete
            BEFORE DELETE ON evidence
            BEGIN
                SELECT RAISE(ABORT, 'persisted evidence is immutable');
            END
            """
        )

    def _migrate_verified_invariant_v7(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Revalidate pre-v7 VERIFIED rows at their original decision time."""

        rows = connection.execute(
            "SELECT * FROM tasks WHERE current_state = ?",
            (TaskStatus.VERIFIED.value,),
        ).fetchall()
        for row in rows:
            verification_json = row["verification_json"]
            is_valid = verification_json is not None
            if is_valid:
                result = self._verification(str(verification_json))
                is_valid = result.status is VerificationStatus.VERIFIED
            if is_valid:
                decision_time = _datetime(row["finished_at"] or row["updated_at"])
                try:
                    self._require_trusted_verification_evidence(
                        connection,
                        row,
                        decision_time=decision_time,
                    )
                except InvalidTransitionError:
                    is_valid = False
            if is_valid:
                continue

            now = datetime.now(UTC)
            connection.execute(
                """
                UPDATE tasks SET current_state = ?, verification_json = NULL,
                    wait_token = NULL, finished_at = NULL,
                    version = version + 1,
                    execution_context_version = execution_context_version + 1,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (TaskStatus.INCONCLUSIVE.value, _iso(now), str(row["task_id"])),
            )
            self._insert_task_event(
                connection,
                row,
                event_type=LifecycleEventType.STATE_TRANSITION,
                occurred_at=now,
                state=TaskStatus.INCONCLUSIVE,
                previous_state=TaskStatus.VERIFIED,
                details={"reason": "verification_commit_invariant_not_established"},
                dedupe_key="migration:v7:verification-invariant-downgrade",
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        if str(self.path) != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _task_row(self, connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"durable task {task_id!r} does not exist")
        return cast(sqlite3.Row, row)

    def _action_row(
        self,
        connection: sqlite3.Connection,
        action_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"durable action {action_id!r} does not exist")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _require_action_version(row: sqlite3.Row, expected_version: int) -> None:
        if int(row["version"]) != expected_version:
            raise ConcurrentUpdateError("durable action changed concurrently")

    @staticmethod
    def _require_action_status(
        row: sqlite3.Row,
        allowed: set[ActionExecutionStatus],
        operation: str,
    ) -> None:
        try:
            current = ActionExecutionStatus(str(row["status"]))
        except ValueError as error:
            raise CorruptStoreError("persisted action status is invalid") from error
        if current not in allowed:
            raise InvalidTransitionError(
                f"cannot {operation} while action is {current.value}"
            )

    def _insert_approval_consumed_event(
        self,
        connection: sqlite3.Connection,
        task_row: sqlite3.Row,
        *,
        approval_id: str,
        request_hash: str,
        required_scope: str,
        consumed_by: str,
        occurred_at: datetime,
    ) -> LifecycleEvent:
        """Record that an approval grant was spent, at most once per approval."""

        return self._insert_task_event(
            connection,
            task_row,
            event_type=LifecycleEventType.APPROVAL_CONSUMED,
            occurred_at=occurred_at,
            name="approval.consumed",
            details={
                "approval_id": approval_id,
                "request_hash": request_hash,
                "required_scope": required_scope,
                "consumed_by": consumed_by,
            },
            dedupe_key=f"approval:{approval_id}:consumed",
        )

    def _recovery_state_row(
        self,
        connection: sqlite3.Connection,
        plan_id: str,
        *,
        expected_version: int | None = None,
    ) -> sqlite3.Row:
        """Load a recovery plan's state row, optionally under optimistic locking."""

        row = connection.execute(
            "SELECT * FROM recovery_state WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if row is None:
            raise TaskNotFoundError(f"recovery plan {plan_id!r} does not exist")
        if expected_version is not None and int(row["version"]) != expected_version:
            raise ConcurrentUpdateError("recovery state changed concurrently")
        return cast(sqlite3.Row, row)

    def _insert_evidence(
        self,
        connection: sqlite3.Connection,
        task_row: sqlite3.Row,
        item: EvidenceItem,
        encoded: str,
    ) -> LifecycleEvent:
        """Insert one evidence row and append its ``evidence.collected`` event.

        Callers own the conflict check against any already-persisted row with
        the same evidence ID; this only writes a row known to be new.
        """

        connection.execute(
            """
            INSERT INTO evidence(
                task_id, evidence_id, evidence_type, item_json, collected_at
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (
                str(task_row["task_id"]),
                item.evidence_id,
                item.type,
                encoded,
                _iso(item.collected_at),
            ),
        )
        return self._insert_task_event(
            connection,
            task_row,
            event_type=LifecycleEventType.EVIDENCE_COLLECTED,
            occurred_at=item.collected_at,
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
            dedupe_key=f"evidence:{item.evidence_id}",
        )

    def _insert_task_event(
        self,
        connection: sqlite3.Connection,
        task_row: sqlite3.Row,
        *,
        event_type: LifecycleEventType,
        occurred_at: datetime,
        details: Mapping[str, Any],
        state: TaskStatus | None = None,
        previous_state: TaskStatus | None = None,
        name: str | None = None,
        dedupe_key: str | None,
    ) -> LifecycleEvent:
        """Append an event whose identity fields come from an existing task row.

        ``state`` defaults to the row's current state, which is what every
        non-transition event records.
        """

        return self._insert_event(
            connection,
            task_id=str(task_row["task_id"]),
            event_type=event_type,
            correlation_id=str(task_row["correlation_id"]),
            worker_id=str(task_row["worker_id"]),
            occurred_at=occurred_at,
            state=self._status(task_row["current_state"]) if state is None else state,
            previous_state=previous_state,
            name=name,
            details=details,
            dedupe_key=dedupe_key,
        )

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        *,
        task_id: str,
        event_type: LifecycleEventType,
        correlation_id: str,
        worker_id: str,
        occurred_at: datetime,
        state: TaskStatus,
        previous_state: TaskStatus | None,
        details: Mapping[str, Any],
        name: str | None = None,
        dedupe_key: str | None,
    ) -> LifecycleEvent:
        sequence_row = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        sequence = int(sequence_row[0])
        event = LifecycleEvent(
            event_type=event_type,
            task_id=task_id,
            correlation_id=correlation_id,
            worker_id=worker_id,
            occurred_at=occurred_at,
            sequence=sequence,
            state=state,
            previous_state=previous_state,
            name=name,
            details=dict(details),
        )
        connection.execute(
            """
            INSERT INTO events(
                task_id, sequence, dedupe_key, event_type, correlation_id,
                worker_id, occurred_at, state, previous_state, name, details_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                sequence,
                dedupe_key,
                event.event_type.value,
                correlation_id,
                worker_id,
                _iso(occurred_at),
                state.value,
                previous_state.value if previous_state is not None else None,
                name,
                self.codec.dumps(dict(details)),
            ),
        )
        return event

    @staticmethod
    def _event_by_dedupe(
        connection: sqlite3.Connection,
        task_id: str,
        dedupe_key: str,
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM events WHERE task_id = ? AND dedupe_key = ?",
                (task_id, dedupe_key),
            ).fetchone(),
        )

    def _stored_task(self, row: sqlite3.Row) -> StoredTask:
        try:
            encoded_contract = str(row["contract_json"])
            stored_digest = str(row["contract_digest"])
            actual_digest = hashlib.sha256(encoded_contract.encode("utf-8")).hexdigest()
            if actual_digest != stored_digest:
                raise CorruptStoreError("persisted contract digest does not match")
            contract_value = self.codec.loads(encoded_contract)
            if not isinstance(contract_value, Mapping):
                raise CorruptStoreError("persisted contract is not an object")
            contract = _contract_snapshot(contract_value)
            task_id = str(row["task_id"])
            if contract.task_id != task_id:
                raise CorruptStoreError("persisted contract task ID does not match")
            errors_value = self.codec.loads(str(row["errors_json"]))
            if not isinstance(errors_value, list):
                raise CorruptStoreError("persisted task errors are not a list")
            verification = (
                None
                if row["verification_json"] is None
                else self._verification(str(row["verification_json"]))
            )
            output = (
                None
                if row["output_json"] is None
                else self.codec.loads(str(row["output_json"]))
            )
            reported = (
                None
                if row["reported_status"] is None
                else WorkerReportedStatus(str(row["reported_status"]))
            )
            return StoredTask(
                task_id=task_id,
                contract=contract,
                contract_digest=stored_digest,
                correlation_id=str(row["correlation_id"]),
                worker_id=str(row["worker_id"]),
                status=self._status(row["current_state"]),
                reported_status=reported,
                output=output,
                errors=tuple(_error(item) for item in errors_value),
                verification=verification,
                version=int(row["version"]),
                execution_context_version=(
                    int(row["execution_context_version"])
                    if "execution_context_version" in row.keys()
                    else 1
                ),
                wait_token=(
                    str(row["wait_token"])
                    if "wait_token" in row.keys() and row["wait_token"] is not None
                    else None
                ),
                timestamps=TaskTimestamps(
                    pending_at=_datetime(row["pending_at"]),
                    started_at=_optional_datetime(row["started_at"]),
                    agent_reported_complete_at=_optional_datetime(
                        row["agent_reported_complete_at"]
                    ),
                    verification_started_at=_optional_datetime(
                        row["verification_started_at"]
                    ),
                    finished_at=_optional_datetime(row["finished_at"]),
                ),
                created_at=_datetime(row["created_at"]),
                updated_at=_datetime(row["updated_at"]),
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            if isinstance(error, CorruptStoreError):
                raise
            raise CorruptStoreError("persisted task record is invalid") from error

    def _stored_action(self, row: sqlite3.Row) -> StoredAction:
        try:
            input_value = self.codec.loads(str(row["input_json"]))
            if not isinstance(input_value, Mapping):
                raise CorruptStoreError("persisted action input is not an object")
            actual_input_hash = (
                "sha256:"
                + hashlib.sha256(
                    self.codec.dumps(input_value).encode("utf-8")
                ).hexdigest()
            )
            if actual_input_hash != str(row["input_hash"]):
                raise CorruptStoreError("persisted action input hash does not match")
            status = ActionExecutionStatus(str(row["status"]))
            policy = (
                None
                if row["policy_json"] is None
                else _action_policy(self.codec.loads(str(row["policy_json"])))
            )
            authorization = (
                None
                if row["authorization_json"] is None
                else _action_authorization(
                    self.codec.loads(str(row["authorization_json"]))
                )
            )
            receipt = (
                None
                if row["receipt_json"] is None
                else _action_receipt(self.codec.loads(str(row["receipt_json"])))
            )
            if receipt is not None and receipt.status is not status:
                raise CorruptStoreError(
                    "persisted receipt status does not match action state"
                )
            return StoredAction(
                action_id=str(row["action_id"]),
                task_id=str(row["task_id"]),
                name=str(row["name"]),
                required_capability=str(row["required_capability"]),
                input=input_value,
                input_hash=str(row["input_hash"]),
                action_hash=str(row["action_hash"]),
                idempotency_key=str(row["idempotency_key"]),
                risk_level=RiskLevel(str(row["risk_level"])),
                requested_by=str(row["requested_by"]),
                requested_at=_datetime(row["requested_at"]),
                timeout=timedelta(seconds=float(row["timeout_seconds"])),
                dry_run=bool(row["dry_run"]),
                status=status,
                policy_decision=policy,
                authorization=authorization,
                receipt=receipt,
                postcondition_status=(
                    ActionPostconditionStatus(str(row["postcondition_status"]))
                    if "postcondition_status" in row.keys()
                    else (
                        ActionPostconditionStatus.PENDING
                        if status is ActionExecutionStatus.EXECUTOR_SUCCEEDED
                        else ActionPostconditionStatus.NOT_STARTED
                    )
                ),
                policy_task_context_version=(
                    int(row["policy_task_context_version"])
                    if "policy_task_context_version" in row.keys()
                    and row["policy_task_context_version"] is not None
                    else None
                ),
                execution_owner_id=_optional_str(row["execution_owner_id"]),
                version=int(row["version"]),
                created_at=_datetime(row["created_at"]),
                updated_at=_datetime(row["updated_at"]),
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            if isinstance(error, CorruptStoreError):
                raise
            raise CorruptStoreError("persisted action record is invalid") from error

    def _event(self, row: sqlite3.Row) -> LifecycleEvent:
        details = self.codec.loads(str(row["details_json"]))
        if not isinstance(details, Mapping):
            raise CorruptStoreError("event details are not an object")
        return LifecycleEvent(
            event_type=LifecycleEventType(str(row["event_type"])),
            task_id=str(row["task_id"]),
            correlation_id=str(row["correlation_id"]),
            worker_id=str(row["worker_id"]),
            occurred_at=_datetime(row["occurred_at"]),
            sequence=int(row["sequence"]),
            state=self._status(row["state"]),
            previous_state=(
                None
                if row["previous_state"] is None
                else self._status(row["previous_state"])
            ),
            name=str(row["name"]) if row["name"] is not None else None,
            details=details,
        )

    def _evidence(self, value: str) -> EvidenceItem:
        item = self.codec.loads(value)
        if not isinstance(item, Mapping):
            raise CorruptStoreError("evidence is not an object")
        content = item.get("content")
        if content is not None and not isinstance(content, (str, bytes)):
            raise CorruptStoreError("evidence content is invalid")
        values: dict[str, Any] = dict(
            evidence_id=str(item["evidence_id"]),
            type=str(item["type"]),
            source=str(item["source"]),
            collected_at=_datetime(item["collected_at"]),
            content=content,
            payload=_optional_mapping(item.get("payload")),
            provenance=_mapping(item.get("provenance", {})),
            artifact_reference=_optional_str(item.get("artifact_reference")),
            checksum=_optional_str(item.get("checksum")),
            metadata=_mapping(item.get("metadata", {})),
            acquisition_method=EvidenceAcquisitionMethod(
                str(
                    item.get(
                        "acquisition_method",
                        EvidenceAcquisitionMethod.AGENT_REPORTED.value,
                    )
                )
            ),
            trust_level=EvidenceTrustLevel(
                int(item.get("trust_level", EvidenceTrustLevel.AGENT_CLAIM))
            ),
            expires_at=_optional_datetime(item.get("expires_at")),
        )
        origin_hash = _optional_str(item.get("origin_hash"))
        trust_origin = _mapping(item.get("trust_origin", {}))
        if origin_hash is None:
            return EvidenceItem(**values)
        return _restore_evidence_origin(
            **values,
            origin_hash=origin_hash,
            trust_origin=trust_origin,
        )

    def _verification(self, value: str) -> VerificationResult:
        item = self.codec.loads(value)
        if not isinstance(item, Mapping):
            raise CorruptStoreError("verification is not an object")
        criteria_value = item.get("criteria", [])
        if not isinstance(criteria_value, list):
            raise CorruptStoreError("verification criteria are invalid")
        return VerificationResult(
            status=VerificationStatus(str(item["status"])),
            criteria=tuple(
                CriterionEvaluation(
                    name=str(criterion["name"]),
                    passed=bool(criterion["passed"]),
                    message=str(criterion["message"]),
                    conclusive=bool(criterion.get("conclusive", True)),
                    awaiting_approval=bool(criterion.get("awaiting_approval", False)),
                    awaiting_runtime_confirmation=bool(
                        criterion.get("awaiting_runtime_confirmation", False)
                    ),
                )
                for criterion in criteria_value
                if isinstance(criterion, Mapping)
            ),
            missing_evidence=tuple(
                str(value) for value in item.get("missing_evidence", [])
            ),
            contradictory_evidence=tuple(
                str(value) for value in item.get("contradictory_evidence", [])
            ),
            message=str(item.get("message", "")),
        )

    def _checkpoint(self, row: sqlite3.Row) -> CheckpointRecord:
        payload = self.codec.loads(str(row["payload_json"]))
        if not isinstance(payload, Mapping):
            raise CorruptStoreError("checkpoint payload is not an object")
        return CheckpointRecord(
            checkpoint_id=str(row["checkpoint_id"]),
            task_id=str(row["task_id"]),
            label=str(row["label"]) if row["label"] is not None else None,
            payload=payload,
            task_version=int(row["task_version"]),
            created_at=_datetime(row["created_at"]),
        )

    @staticmethod
    def _approval(row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=str(row["approval_id"]),
            task_id=str(row["task_id"]),
            approval_key=str(row["approval_key"]),
            approved=(None if row["approved"] is None else bool(row["approved"])),
            approved_by=(
                str(row["approved_by"]) if row["approved_by"] is not None else None
            ),
            reason=str(row["reason"]),
            created_at=_datetime(row["created_at"]),
            decided_at=_optional_datetime(row["decided_at"]),
            capability=(
                str(row["capability"]) if row["capability"] is not None else None
            ),
            idempotency_key=(
                str(row["idempotency_key"])
                if row["idempotency_key"] is not None
                else None
            ),
        )

    @staticmethod
    def _approval_record_from_stored(
        stored: StoredApproval,
        *,
        capability: str | None = None,
        idempotency_key: str | None = None,
    ) -> ApprovalRecord:
        decision = stored.decision
        return ApprovalRecord(
            approval_id=stored.request.approval_id,
            task_id=stored.request.task_id,
            approval_key=stored.request.target_hash,
            approved=None if decision is None else decision.approved,
            approved_by=None if decision is None else decision.approver.subject,
            reason=stored.request.reason if decision is None else decision.reason,
            created_at=stored.request.created_at,
            decided_at=None if decision is None else decision.decided_at,
            capability=capability,
            idempotency_key=idempotency_key,
        )

    def _stored_approval(self, row: sqlite3.Row) -> StoredApproval:
        """Decode and integrity-check a schema-v4 approval row."""

        try:
            required_request_fields = (
                "approval_id",
                "task_id",
                "target_id",
                "target_hash",
                "request_hash",
                "required_scope",
                "risk_level",
                "request_reason",
                "created_at",
                "expires_at",
                "request_metadata_json",
            )
            if any(row[field] is None for field in required_request_fields):
                raise CorruptStoreError(
                    "persisted approval request is missing required fields"
                )
            request_metadata = self.codec.loads(str(row["request_metadata_json"]))
            if not isinstance(request_metadata, Mapping):
                raise CorruptStoreError("approval request metadata is invalid")
            request = ApprovalRequest(
                approval_id=str(row["approval_id"]),
                task_id=str(row["task_id"]),
                target_id=str(row["target_id"]),
                target_hash=str(row["target_hash"]),
                required_scope=str(row["required_scope"]),
                risk_level=RiskLevel(str(row["risk_level"])),
                reason=str(row["request_reason"]),
                created_at=_datetime(row["created_at"]),
                expires_at=_datetime(row["expires_at"]),
                one_time_use=bool(row["one_time_use"]),
                metadata=request_metadata,
            )
            if request.request_hash != str(row["request_hash"]):
                raise CorruptStoreError("approval request hash does not match")
            decision: ApprovalDecision | None = None
            if row["decision_id"] is not None:
                if any(
                    row[field] is None
                    for field in (
                        "approved",
                        "approved_by",
                        "decided_at",
                        "decision_metadata_json",
                        "approver_identity_json",
                    )
                ):
                    raise CorruptStoreError("persisted approval decision is incomplete")
                identity_value = self.codec.loads(str(row["approver_identity_json"]))
                metadata_value = self.codec.loads(str(row["decision_metadata_json"]))
                if not isinstance(metadata_value, Mapping):
                    raise CorruptStoreError("approval decision metadata is invalid")
                decision = ApprovalDecision(
                    decision_id=str(row["decision_id"]),
                    approval_id=request.approval_id,
                    request_hash=request.request_hash,
                    approved=bool(row["approved"]),
                    approver=_approver_identity(identity_value),
                    decided_at=_datetime(row["decided_at"]),
                    reason=str(row["reason"]),
                    metadata=metadata_value,
                )
                if decision.decided_at < request.created_at:
                    raise CorruptStoreError(
                        "persisted approval decision predates its request"
                    )
            elif any(
                row[field] is not None
                for field in (
                    "approved",
                    "approved_by",
                    "decided_at",
                    "decision_metadata_json",
                    "approver_identity_json",
                )
            ):
                raise CorruptStoreError(
                    "persisted approval has decision data without a decision ID"
                )
            revocation: ApprovalRevocation | None = None
            if row["revocation_id"] is not None:
                if any(
                    row[field] is None
                    for field in (
                        "revoked_at",
                        "revoked_by_json",
                        "revocation_reason",
                        "revocation_metadata_json",
                    )
                ):
                    raise CorruptStoreError(
                        "persisted approval revocation is incomplete"
                    )
                revoked_by_value = self.codec.loads(str(row["revoked_by_json"]))
                revocation_metadata = self.codec.loads(
                    str(row["revocation_metadata_json"])
                )
                if not isinstance(revocation_metadata, Mapping):
                    raise CorruptStoreError("approval revocation metadata is invalid")
                revocation = ApprovalRevocation(
                    revocation_id=str(row["revocation_id"]),
                    approval_id=request.approval_id,
                    request_hash=request.request_hash,
                    revoked_by=_approver_identity(revoked_by_value),
                    revoked_at=_datetime(row["revoked_at"]),
                    reason=str(row["revocation_reason"]),
                    metadata=revocation_metadata,
                )
                if revocation.revoked_at < request.created_at:
                    raise CorruptStoreError(
                        "persisted approval revocation predates its request"
                    )
            elif any(
                row[field] is not None
                for field in (
                    "revoked_at",
                    "revoked_by_json",
                    "revocation_reason",
                    "revocation_metadata_json",
                )
            ):
                raise CorruptStoreError(
                    "persisted approval has revocation data without a revocation ID"
                )
            if (row["consumed_at"] is None) != (row["consumed_by"] is None):
                raise CorruptStoreError("persisted approval consumption is incomplete")
            if row["consumed_at"] is not None and (
                decision is None or not decision.approved
            ):
                raise CorruptStoreError(
                    "persisted approval was consumed without an approved decision"
                )
            if int(row["version"]) < 1:
                raise CorruptStoreError("persisted approval version is invalid")
            return StoredApproval(
                request=request,
                decision=decision,
                revocation=revocation,
                consumed_at=_optional_datetime(row["consumed_at"]),
                consumed_by=_optional_str(row["consumed_by"]),
                version=int(row["version"]),
            )
        except (SerializationError, TypeError, ValueError, KeyError) as error:
            if isinstance(error, CorruptStoreError):
                raise
            raise CorruptStoreError("persisted approval is invalid") from error

    @staticmethod
    def _status(value: Any) -> TaskStatus:
        try:
            return TaskStatus(str(value))
        except ValueError as error:
            raise CorruptStoreError(
                f"invalid persisted task status {value!r}"
            ) from error


def contract_snapshot(
    contract: TaskContract[Any, Any],
    codec: JsonCodec | None = None,
) -> ContractSnapshot:
    """Build the stable, safe persisted declaration for a task contract."""

    resolved_codec = codec or SafeJsonCodec()
    input_value = resolved_codec.loads(resolved_codec.dumps(contract.input))
    metadata = resolved_codec.loads(resolved_codec.dumps(dict(contract.metadata)))
    if not isinstance(metadata, Mapping):
        raise SerializationError("contract metadata must serialize to an object")
    criteria = tuple(
        _criterion_snapshot(item, resolved_codec)
        for item in contract.acceptance_criteria
    )
    requirements = tuple(
        {
            "evidence_type": item.evidence_type,
            "description": item.description,
            "minimum_count": item.minimum_count,
            "consistent_fields": list(item.consistent_fields),
            "minimum_trust_level": int(item.minimum_trust_level),
            "max_age_seconds": (
                item.max_age.total_seconds() if item.max_age is not None else None
            ),
        }
        for item in contract.required_evidence
    )
    return ContractSnapshot(
        task_id=contract.task_id,
        objective=contract.objective,
        input=input_value,
        acceptance_criteria=criteria,
        required_evidence=requirements,
        allowed_capabilities=tuple(sorted(contract.allowed_capabilities)),
        risk_level=contract.risk_level.value,
        timeout_seconds=contract.timeout.total_seconds(),
        idempotency_key=contract.idempotency_key,
        metadata=metadata,
    )


def _criterion_snapshot(criterion: Any, codec: JsonCodec) -> Mapping[str, Any]:
    common = {
        "name": str(criterion.name),
        "description": str(criterion.description),
    }
    if isinstance(criterion, FieldEqualsCriterion):
        expected = codec.loads(codec.dumps(criterion.expected))
        return {
            **common,
            "kind": "field_equals",
            "field_path": criterion.field_path,
            "expected": expected,
            "evidence_type": criterion.evidence_type,
        }
    if isinstance(criterion, CollectionNotEmptyCriterion):
        return {
            **common,
            "kind": "collection_not_empty",
            "field_path": criterion.field_path,
            "evidence_type": criterion.evidence_type,
        }
    if isinstance(criterion, RuntimeConfirmationCriterion):
        return {
            **common,
            "kind": "runtime_confirmation",
            "confirmation_key": criterion.confirmation_key,
        }
    if isinstance(criterion, ApprovalCriterion):
        return {
            **common,
            "kind": "approval",
            "approval_key": criterion.approval_key,
        }
    if isinstance(criterion, DeclaredConditionCriterion):
        predicate = criterion.predicate
        return {
            **common,
            "kind": "application_condition",
            "implementation": (
                f"{type(criterion).__module__}.{type(criterion).__qualname__}"
            ),
            "predicate": (
                f"{getattr(predicate, '__module__', '')}."
                f"{getattr(predicate, '__qualname__', type(predicate).__qualname__)}"
            ),
        }
    return {
        **common,
        "kind": "application_criterion",
        "implementation": (
            f"{type(criterion).__module__}.{type(criterion).__qualname__}"
        ),
    }


def _contract_snapshot(value: Mapping[str, Any]) -> ContractSnapshot:
    if int(value.get("schema_version", 0)) != CONTRACT_SCHEMA_VERSION:
        raise CorruptStoreError("unsupported persisted contract schema")
    criteria = value.get("acceptance_criteria")
    requirements = value.get("required_evidence")
    capabilities = value.get("allowed_capabilities")
    metadata = value.get("metadata")
    if not isinstance(criteria, list) or not all(
        isinstance(item, Mapping) for item in criteria
    ):
        raise CorruptStoreError("persisted acceptance criteria are invalid")
    if not isinstance(requirements, list) or not all(
        isinstance(item, Mapping) for item in requirements
    ):
        raise CorruptStoreError("persisted evidence requirements are invalid")
    if not isinstance(capabilities, list) or not all(
        isinstance(item, str) for item in capabilities
    ):
        raise CorruptStoreError("persisted capabilities are invalid")
    if not isinstance(metadata, Mapping):
        raise CorruptStoreError("persisted metadata is invalid")
    return ContractSnapshot(
        task_id=str(value["task_id"]),
        objective=str(value["objective"]),
        input=value.get("input"),
        acceptance_criteria=tuple(criteria),
        required_evidence=tuple(requirements),
        allowed_capabilities=tuple(capabilities),
        risk_level=str(value["risk_level"]),
        timeout_seconds=float(value["timeout_seconds"]),
        idempotency_key=str(value["idempotency_key"]),
        metadata=metadata,
        schema_version=int(value["schema_version"]),
    )


def _evidence_dict(item: EvidenceItem) -> dict[str, Any]:
    return {
        "evidence_id": item.evidence_id,
        "type": item.type,
        "source": item.source,
        "collected_at": item.collected_at,
        "content": item.content,
        "payload": item.payload,
        "provenance": item.provenance,
        "artifact_reference": item.artifact_reference,
        "checksum": item.checksum,
        "metadata": item.metadata,
        "acquisition_method": item.acquisition_method.value,
        "trust_level": int(item.trust_level),
        "expires_at": item.expires_at,
        "trust_origin": item.trust_origin,
        "origin_hash": item.origin_hash,
    }


def _error_dict(error: TaskError) -> dict[str, Any]:
    return {
        "code": error.code.value,
        "message": error.message,
        "error_type": error.error_type,
    }


def _error(value: Any) -> TaskError:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted task error is invalid")
    return TaskError(
        code=TaskErrorCode(str(value["code"])),
        message=str(value["message"]),
        error_type=_optional_str(value.get("error_type")),
    )


def _verification_dict(result: VerificationResult) -> dict[str, Any]:
    return {
        "status": result.status.value,
        "criteria": [
            {
                "name": item.name,
                "passed": item.passed,
                "message": item.message,
                "conclusive": item.conclusive,
                "awaiting_approval": item.awaiting_approval,
                "awaiting_runtime_confirmation": item.awaiting_runtime_confirmation,
            }
            for item in result.criteria
        ],
        "missing_evidence": list(result.missing_evidence),
        "contradictory_evidence": list(result.contradictory_evidence),
        "message": result.message,
    }


def _action_policy_dict(decision: ActionPolicyDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reasons": list(decision.reasons),
        "requires_approval": decision.requires_approval,
        "decided_at": decision.decided_at,
        "decided_by": decision.decided_by,
    }


def _action_policy(value: Any) -> ActionPolicyDecision:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted action policy is not an object")
    reasons = value.get("reasons")
    if not isinstance(reasons, list):
        raise CorruptStoreError("persisted action policy reasons are invalid")
    return ActionPolicyDecision(
        allowed=bool(value["allowed"]),
        reasons=tuple(str(item) for item in reasons),
        requires_approval=bool(value["requires_approval"]),
        decided_at=_datetime(value["decided_at"]),
        decided_by=str(value["decided_by"]),
    )


def _action_authorization_dict(
    authorization: PreActionAuthorization,
) -> dict[str, Any]:
    return {
        "authorized": authorization.authorized,
        "reason": authorization.reason,
        "evaluated_preconditions": [
            {
                "name": item.name,
                "passed": item.passed,
                "message": item.message,
            }
            for item in authorization.evaluated_preconditions
        ],
        "approved_by": authorization.approved_by,
        "authorized_at": authorization.authorized_at,
        "awaiting_approval": authorization.awaiting_approval,
    }


def _action_authorization(value: Any) -> PreActionAuthorization:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted action authorization is not an object")
    preconditions = value.get("evaluated_preconditions")
    if not isinstance(preconditions, list) or not all(
        isinstance(item, Mapping) for item in preconditions
    ):
        raise CorruptStoreError("persisted action preconditions are invalid")
    return PreActionAuthorization(
        authorized=bool(value["authorized"]),
        reason=str(value["reason"]),
        evaluated_preconditions=tuple(
            ActionConditionResult(
                name=str(item["name"]),
                passed=bool(item["passed"]),
                message=str(item["message"]),
            )
            for item in preconditions
        ),
        approved_by=_optional_str(value.get("approved_by")),
        authorized_at=_datetime(value["authorized_at"]),
        awaiting_approval=bool(value.get("awaiting_approval", False)),
    )


def _action_receipt_dict(receipt: ActionReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "action_id": receipt.action_id,
        "executor_id": receipt.executor_id,
        "status": receipt.status.value,
        "action_hash": receipt.action_hash,
        "input_hash": receipt.input_hash,
        "idempotency_key": receipt.idempotency_key,
        "started_at": receipt.started_at,
        "finished_at": receipt.finished_at,
        "output": receipt.output,
        "message": receipt.message,
        "error_type": receipt.error_type,
        "output_hash": receipt.output_hash,
    }


def _action_receipt(value: Any) -> ActionReceipt:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted action receipt is not an object")
    receipt = ActionReceipt(
        receipt_id=str(value["receipt_id"]),
        action_id=str(value["action_id"]),
        executor_id=str(value["executor_id"]),
        status=ActionExecutionStatus(str(value["status"])),
        action_hash=str(value["action_hash"]),
        input_hash=str(value["input_hash"]),
        idempotency_key=str(value["idempotency_key"]),
        started_at=_datetime(value["started_at"]),
        finished_at=_datetime(value["finished_at"]),
        output=value.get("output"),
        message=str(value.get("message", "")),
        error_type=_optional_str(value.get("error_type")),
    )
    if value.get("output_hash") != receipt.output_hash:
        raise CorruptStoreError("persisted action receipt output hash does not match")
    return receipt


def _action_finish_event(status: ActionExecutionStatus) -> LifecycleEventType:
    return {
        ActionExecutionStatus.EXECUTOR_SUCCEEDED: (
            LifecycleEventType.ACTION_EXECUTOR_SUCCEEDED
        ),
        ActionExecutionStatus.FAILED: LifecycleEventType.ACTION_EXECUTION_FAILED,
        ActionExecutionStatus.UNKNOWN: LifecycleEventType.ACTION_EXECUTION_UNKNOWN,
        ActionExecutionStatus.CANCELLED: LifecycleEventType.ACTION_EXECUTION_FAILED,
        ActionExecutionStatus.DRY_RUN: LifecycleEventType.ACTION_DRY_RUN_COMPLETED,
    }[status]


def _runtime_confirmation_dict(confirmation: RuntimeConfirmation) -> dict[str, Any]:
    return {
        "confirmation_id": confirmation.confirmation_id,
        "action_id": confirmation.action_id,
        "capability": confirmation.capability,
        "idempotency_key": confirmation.idempotency_key,
        "supported": confirmation.supported,
        "safe": confirmation.safe,
        "confirmed_at": confirmation.confirmed_at,
        "confirmed_by": confirmation.confirmed_by,
        "reason": confirmation.reason,
        "target_hash": confirmation.target_hash,
    }


def _runtime_confirmation(value: Any) -> RuntimeConfirmation:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted preflight confirmation is not an object")
    return RuntimeConfirmation(
        confirmation_id=str(value["confirmation_id"]),
        action_id=str(value["action_id"]),
        capability=str(value["capability"]),
        idempotency_key=str(value["idempotency_key"]),
        supported=bool(value["supported"]),
        safe=bool(value["safe"]),
        confirmed_at=_datetime(value["confirmed_at"]),
        confirmed_by=str(value["confirmed_by"]),
        reason=str(value["reason"]),
        target_hash=_optional_str(value.get("target_hash")),
    )


def _approver_identity_dict(identity: ApproverIdentity) -> dict[str, Any]:
    return {
        "subject": identity.subject,
        "issuer": identity.issuer,
        "authenticated_at": identity.authenticated_at,
        "authentication_method": identity.authentication_method,
        "claims": dict(identity.claims),
    }


def _approver_identity(value: Any) -> ApproverIdentity:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted approver identity is not an object")
    claims = value.get("claims", {})
    if not isinstance(claims, Mapping):
        raise CorruptStoreError("persisted approver claims are invalid")
    return ApproverIdentity(
        subject=str(value["subject"]),
        issuer=str(value["issuer"]),
        authenticated_at=_datetime(value["authenticated_at"]),
        authentication_method=str(value["authentication_method"]),
        claims=claims,
    )


def _recovery_plan_dict(plan: RecoveryPlan) -> dict[str, Any]:
    return {
        "plan_id": plan.plan_id,
        "plan_hash": plan.plan_hash,
        "task_id": plan.task_id,
        "proposed_by": plan.proposed_by,
        "failure_diagnosis": plan.failure_diagnosis,
        "context_reference": plan.context_reference,
        "declared_recovery_capability": plan.declared_recovery_capability,
        "risk_level": plan.risk_level.value,
        "approval_required": plan.approval_required,
        "preconditions": [
            {"name": item.name, "description": item.description}
            for item in plan.preconditions
        ],
        "postconditions": [
            {
                "name": item.name,
                "description": item.description,
                "evidence_type": item.evidence_type,
                "required": item.required,
                "provider_identity": item.provider_identity,
                "provider_configuration": dict(item.provider_configuration),
            }
            for item in plan.postconditions
        ],
        "compensation_id": plan.compensation_id,
        "created_at": plan.created_at,
        "actions": [
            {
                "action_id": action.action_id,
                "action_hash": action.action_hash,
                "capability": action.capability,
                "idempotency_key": action.idempotency_key,
                "reason": action.reason,
                "parameters": dict(action.parameters),
                "handler_identity": action.handler_identity,
                "handler_configuration": dict(action.handler_configuration),
            }
            for action in plan.actions
        ],
    }


def _recovery_receipt_dict(receipt: RecoveryExecutionReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "plan_id": receipt.plan_id,
        "action_id": receipt.action_id,
        "action_hash": receipt.action_hash,
        "executor_id": receipt.executor_id,
        "status": receipt.status.value,
        "started_at": receipt.started_at,
        "finished_at": receipt.finished_at,
        "output": receipt.output,
        "output_hash": receipt.output_hash,
        "message": receipt.message,
        "error_type": receipt.error_type,
    }


def _recovery_receipt(value: Any) -> RecoveryExecutionReceipt:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted recovery receipt is not an object")
    receipt = RecoveryExecutionReceipt(
        receipt_id=str(value["receipt_id"]),
        plan_id=str(value["plan_id"]),
        action_id=str(value["action_id"]),
        action_hash=str(value["action_hash"]),
        executor_id=str(value["executor_id"]),
        status=RecoveryStatus(str(value["status"])),
        started_at=_datetime(value["started_at"]),
        finished_at=_datetime(value["finished_at"]),
        output=value.get("output"),
        message=str(value.get("message", "")),
        error_type=_optional_str(value.get("error_type")),
    )
    if value.get("output_hash") != receipt.output_hash:
        raise CorruptStoreError("recovery receipt output hash does not match")
    return receipt


def _timestamp_column(status: TaskStatus) -> str | None:
    return {
        TaskStatus.RUNNING: "started_at",
        TaskStatus.AGENT_REPORTED_COMPLETE: "agent_reported_complete_at",
        TaskStatus.VERIFYING: "verification_started_at",
        TaskStatus.VERIFIED: "finished_at",
        TaskStatus.FAILED: "finished_at",
    }.get(status)


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("durable timestamps must be timezone-aware")
    return value.isoformat()


def _datetime(value: Any) -> datetime:
    result = datetime.fromisoformat(str(value))
    if result.tzinfo is None or result.utcoffset() is None:
        raise CorruptStoreError("persisted timestamp is not timezone-aware")
    return result


def _optional_datetime(value: Any) -> datetime | None:
    return None if value is None else _datetime(value)


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CorruptStoreError("persisted value is not an object")
    return value


def _optional_mapping(value: Any) -> Mapping[str, Any] | None:
    return None if value is None else _mapping(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


_MIGRATIONS: Mapping[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE schema_migrations(
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE tasks(
            task_id TEXT PRIMARY KEY,
            contract_json TEXT NOT NULL,
            contract_digest TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            worker_id TEXT NOT NULL,
            current_state TEXT NOT NULL,
            reported_status TEXT,
            output_json TEXT,
            errors_json TEXT NOT NULL,
            verification_json TEXT,
            version INTEGER NOT NULL CHECK(version > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            pending_at TEXT NOT NULL,
            started_at TEXT,
            agent_reported_complete_at TEXT,
            verification_started_at TEXT,
            finished_at TEXT
        )
        """,
        """
        CREATE TABLE evidence(
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            evidence_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            item_json TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            PRIMARY KEY(task_id, evidence_id)
        )
        """,
        """
        CREATE TABLE events(
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL CHECK(sequence > 0),
            dedupe_key TEXT,
            event_type TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            worker_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            state TEXT NOT NULL,
            previous_state TEXT,
            name TEXT,
            details_json TEXT NOT NULL,
            PRIMARY KEY(task_id, sequence),
            UNIQUE(task_id, dedupe_key)
        )
        """,
        """
        CREATE TABLE idempotency_records(
            scope TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(scope, idempotency_key)
        )
        """,
        "CREATE INDEX evidence_task_type_idx ON evidence(task_id, evidence_type)",
        "CREATE INDEX events_task_time_idx ON events(task_id, occurred_at)",
    ),
    2: (
        "ALTER TABLE tasks ADD COLUMN wait_token TEXT",
        """
        CREATE TABLE checkpoints(
            checkpoint_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            label TEXT,
            payload_json TEXT NOT NULL,
            task_version INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE INDEX checkpoints_task_version_idx
        ON checkpoints(task_id, task_version)
        """,
        """
        CREATE TABLE approvals(
            approval_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            approval_key TEXT NOT NULL,
            approved INTEGER,
            approved_by TEXT,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            capability TEXT,
            idempotency_key TEXT
        )
        """,
        "CREATE INDEX approvals_task_key_idx ON approvals(task_id, approval_key)",
        """
        CREATE TABLE runtime_confirmations(
            confirmation_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            confirmation_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            confirmed_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE recovery_state(
            plan_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            updated_at TEXT NOT NULL
        )
        """,
    ),
    3: (
        """
        CREATE TABLE actions(
            action_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            required_capability TEXT NOT NULL,
            input_json TEXT NOT NULL,
            input_hash TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            timeout_seconds REAL NOT NULL CHECK(timeout_seconds > 0),
            dry_run INTEGER NOT NULL CHECK(dry_run IN (0, 1)),
            status TEXT NOT NULL,
            policy_json TEXT,
            authorization_json TEXT,
            receipt_json TEXT,
            execution_owner_id TEXT,
            version INTEGER NOT NULL CHECK(version > 0),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            UNIQUE(task_id, required_capability, idempotency_key, dry_run)
        )
        """,
        """
        CREATE INDEX actions_task_status_idx ON actions(task_id, status)
        """,
        """
        CREATE TABLE action_evidence(
            action_id TEXT NOT NULL REFERENCES actions(action_id) ON DELETE CASCADE,
            task_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            postcondition_name TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY(action_id, evidence_id),
            FOREIGN KEY(task_id, evidence_id)
                REFERENCES evidence(task_id, evidence_id) ON DELETE RESTRICT
        )
        """,
    ),
    4: (
        "ALTER TABLE approvals ADD COLUMN target_id TEXT",
        "ALTER TABLE approvals ADD COLUMN target_hash TEXT",
        "ALTER TABLE approvals ADD COLUMN request_hash TEXT",
        "ALTER TABLE approvals ADD COLUMN required_scope TEXT",
        "ALTER TABLE approvals ADD COLUMN risk_level TEXT",
        "ALTER TABLE approvals ADD COLUMN request_reason TEXT",
        "ALTER TABLE approvals ADD COLUMN expires_at TEXT",
        "ALTER TABLE approvals ADD COLUMN one_time_use INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE approvals ADD COLUMN request_metadata_json TEXT",
        "ALTER TABLE approvals ADD COLUMN decision_id TEXT",
        "ALTER TABLE approvals ADD COLUMN decision_metadata_json TEXT",
        "ALTER TABLE approvals ADD COLUMN approver_identity_json TEXT",
        "ALTER TABLE approvals ADD COLUMN revoked_at TEXT",
        "ALTER TABLE approvals ADD COLUMN revocation_id TEXT",
        "ALTER TABLE approvals ADD COLUMN revoked_by_json TEXT",
        "ALTER TABLE approvals ADD COLUMN revocation_reason TEXT",
        "ALTER TABLE approvals ADD COLUMN revocation_metadata_json TEXT",
        "ALTER TABLE approvals ADD COLUMN consumed_at TEXT",
        "ALTER TABLE approvals ADD COLUMN consumed_by TEXT",
        "ALTER TABLE approvals ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
        """
        CREATE UNIQUE INDEX approvals_decision_id_idx
        ON approvals(decision_id) WHERE decision_id IS NOT NULL
        """,
        """
        CREATE UNIQUE INDEX approvals_revocation_id_idx
        ON approvals(revocation_id) WHERE revocation_id IS NOT NULL
        """,
        """
        CREATE INDEX approvals_exact_target_idx
        ON approvals(task_id, target_hash, required_scope)
        """,
        "ALTER TABLE recovery_state ADD COLUMN plan_hash TEXT",
        "ALTER TABLE recovery_state ADD COLUMN execution_owner_id TEXT",
        "ALTER TABLE recovery_state ADD COLUMN receipt_json TEXT",
        "ALTER TABLE recovery_state ADD COLUMN approval_id TEXT",
        "ALTER TABLE recovery_state ADD COLUMN started_at TEXT",
        "ALTER TABLE recovery_state ADD COLUMN finished_at TEXT",
        """
        CREATE TABLE recovery_evidence(
            plan_id TEXT NOT NULL REFERENCES recovery_state(plan_id)
                ON DELETE CASCADE,
            task_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            postcondition_name TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY(plan_id, evidence_id),
            FOREIGN KEY(task_id, evidence_id)
                REFERENCES evidence(task_id, evidence_id) ON DELETE RESTRICT
        )
        """,
    ),
    5: (),
    6: (
        """
        ALTER TABLE actions ADD COLUMN postcondition_status TEXT NOT NULL
        DEFAULT 'not_started'
        CHECK(postcondition_status IN ('not_started', 'pending', 'completed'))
        """,
        """
        UPDATE actions SET postcondition_status = 'pending'
        WHERE status = 'executor_succeeded'
        """,
    ),
    7: (
        """
        ALTER TABLE tasks ADD COLUMN execution_context_version INTEGER NOT NULL
        DEFAULT 1 CHECK(execution_context_version > 0)
        """,
        """
        ALTER TABLE actions ADD COLUMN policy_task_context_version INTEGER
        CHECK(policy_task_context_version > 0)
        """,
        """
        CREATE TABLE action_postconditions(
            action_id TEXT NOT NULL REFERENCES actions(action_id) ON DELETE CASCADE,
            postcondition_name TEXT NOT NULL,
            evidence_count INTEGER NOT NULL CHECK(evidence_count >= 0),
            completed_at TEXT NOT NULL,
            PRIMARY KEY(action_id, postcondition_name)
        )
        """,
    ),
}
