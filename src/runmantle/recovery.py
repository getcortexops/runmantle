"""Recovery contracts and the compatibility in-memory recovery executor."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import StrEnum
from threading import Lock
from types import MappingProxyType
from typing import Any, Protocol

from ._validation import (
    require_aware,
    require_non_empty,
    require_non_empty_attributes,
    require_unique,
)
from .capabilities import CapabilityDeclaration, CapabilityRegistry
from .contracts import RiskLevel, TaskContract, TaskStatus
from .evidence import Clock, EvidenceCollection, EvidenceItem, utc_now
from .serialization import SafeJsonCodec
from .telemetry import (
    EventSink,
    LifecycleEvent,
    LifecycleEventType,
    NullEventSink,
)


class RecoveryStatus(StrEnum):
    PLANNED = "planned"
    DRY_RUN = "dry_run"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_PREFLIGHT_CONFIRMATION = "awaiting_preflight_confirmation"
    AWAITING_RUNTIME_CONFIRMATION = "awaiting_runtime_confirmation"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    EXECUTOR_SUCCEEDED = "executor_succeeded"
    POSTCONDITIONS_SATISFIED = "postconditions_satisfied"
    POSTCONDITION_FAILED = "postcondition_failed"
    VERIFIED = "verified"
    UNKNOWN = "unknown"
    RUNTIME_CONFIRMED = "runtime_confirmed"
    FAILED = "failed"
    DUPLICATE_PREVENTED = "duplicate_prevented"


class RecoveryReasonCode(StrEnum):
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    RECOVERY_NOT_SUPPORTED = "recovery_not_supported"
    TASK_MISMATCH = "task_mismatch"
    INVALID_TASK_STATE = "invalid_task_state"
    IDEMPOTENCY_MISMATCH = "idempotency_mismatch"
    RISK_EXCEEDS_CAPABILITY = "risk_exceeds_capability"
    POLICY_DENIED = "policy_denied"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_HASH_MISMATCH = "approval_hash_mismatch"
    PREFLIGHT_CONFIRMATION_REQUIRED = "preflight_confirmation_required"
    PREFLIGHT_CONFIRMATION_REJECTED = "preflight_confirmation_rejected"
    RUNTIME_CONFIRMATION_REQUIRED = "runtime_confirmation_required"
    RUNTIME_CONFIRMATION_REJECTED = "runtime_confirmation_rejected"
    DUPLICATE_IDEMPOTENCY_KEY = "duplicate_idempotency_key"
    EXECUTOR_UNAVAILABLE = "executor_unavailable"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_INTERRUPTED = "execution_interrupted"
    PRECONDITION_FAILED = "precondition_failed"
    POSTCONDITION_FAILED = "postcondition_failed"
    OUTCOME_NOT_VERIFIED = "outcome_not_verified"
    DRY_RUN_COMPLETE = "dry_run_complete"
    EXECUTED = "executed"


@dataclass(frozen=True, slots=True)
class RecoveryAction:
    """A proposed action; construction grants no execution authority."""

    action_id: str
    capability: str
    idempotency_key: str
    reason: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    handler_identity: str = "application.recovery_handler.unspecified"
    handler_configuration: Mapping[str, Any] = field(default_factory=dict)
    action_hash: str = field(init=False)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("action_id", "capability", "idempotency_key", "reason"),
            prefix="recovery action",
        )
        codec = SafeJsonCodec()
        parameters = codec.loads(codec.dumps(dict(self.parameters)))
        handler_configuration = codec.loads(
            codec.dumps(dict(self.handler_configuration))
        )
        if not isinstance(parameters, Mapping):
            raise TypeError("recovery action parameters must be a JSON object")
        if not isinstance(handler_configuration, Mapping):
            raise TypeError("recovery handler configuration must be a JSON object")
        require_non_empty(self.handler_identity, "recovery handler identity")
        object.__setattr__(self, "parameters", _freeze_mapping(parameters))
        object.__setattr__(
            self,
            "handler_configuration",
            _freeze_mapping(handler_configuration),
        )
        object.__setattr__(
            self,
            "action_hash",
            _sha256(
                codec.dumps(
                    {
                        "action_id": self.action_id,
                        "capability": self.capability,
                        "idempotency_key": self.idempotency_key,
                        "reason": self.reason,
                        "parameters": parameters,
                        "handler_identity": self.handler_identity,
                        "handler_configuration": handler_configuration,
                    }
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class RecoveryExecutionReceipt:
    """Executor receipt; never equivalent to postcondition or final verification."""

    receipt_id: str
    plan_id: str
    action_id: str
    action_hash: str
    executor_id: str
    status: RecoveryStatus
    started_at: datetime
    finished_at: datetime
    output: Any = None
    message: str = ""
    error_type: str | None = None
    output_hash: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("receipt_id", "plan_id", "action_id", "action_hash", "executor_id"),
            prefix="recovery execution receipt",
        )
        require_aware(self.started_at, "recovery receipt started_at must be aware")
        require_aware(self.finished_at, "recovery receipt finished_at must be aware")
        if self.finished_at < self.started_at:
            raise ValueError("recovery receipt cannot finish before it starts")
        if self.status not in {
            RecoveryStatus.EXECUTOR_SUCCEEDED,
            RecoveryStatus.FAILED,
            RecoveryStatus.UNKNOWN,
            RecoveryStatus.DRY_RUN,
        }:
            raise ValueError("invalid recovery receipt status")
        if self.output is not None:
            object.__setattr__(
                self,
                "output_hash",
                _sha256(SafeJsonCodec().dumps(self.output)),
            )


@dataclass(frozen=True, slots=True)
class RecoveryExecutorResult:
    """Explicit application handler result before external verification."""

    succeeded: bool
    output: Any = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class RecoveryConditionResult:
    name: str
    passed: bool
    message: str

    def __post_init__(self) -> None:
        require_non_empty(self.name, "recovery condition name")
        require_non_empty(self.message, "recovery condition message")


RecoveryPreconditionEvaluator = Callable[
    ["RecoveryPlan", RecoveryAction, TaskContract[Any, Any]],
    bool | RecoveryConditionResult,
]


@dataclass(frozen=True, slots=True)
class RecoveryPrecondition:
    """Application check re-evaluated immediately before recovery execution."""

    name: str
    description: str
    evaluator: RecoveryPreconditionEvaluator = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "recovery precondition name")
        require_non_empty(self.description, "recovery precondition description")
        if not callable(self.evaluator):
            raise TypeError("recovery precondition evaluator must be callable")

    def evaluate(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        contract: TaskContract[Any, Any],
    ) -> RecoveryConditionResult:
        result = self.evaluator(plan, action, contract)
        if isinstance(result, RecoveryConditionResult):
            return result
        return RecoveryConditionResult(
            name=self.name,
            passed=bool(result),
            message=(
                "recovery precondition satisfied"
                if result
                else "recovery precondition was not satisfied"
            ),
        )


class RecoveryEvidenceProvider(Protocol):
    async def acquire(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: RecoveryExecutionReceipt,
    ) -> EvidenceItem | EvidenceCollection | Sequence[EvidenceItem]: ...


@dataclass(frozen=True, slots=True)
class RecoveryPostcondition:
    """Independent evidence acquisition boundary after recovery execution."""

    name: str
    description: str
    provider: RecoveryEvidenceProvider = field(compare=False, repr=False)
    evidence_type: str | None = None
    required: bool = True
    provider_identity: str | None = None
    provider_configuration: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "recovery postcondition name")
        require_non_empty(self.description, "recovery postcondition description")
        if not callable(getattr(self.provider, "acquire", None)):
            raise TypeError("recovery postcondition provider must implement acquire")
        identity = self.provider_identity or _callable_identity(self.provider.acquire)
        require_non_empty(identity, "recovery postcondition provider identity")
        configuration = (
            self.provider_configuration
            if self.provider_configuration
            else _stable_provider_configuration(self.provider)
        )
        object.__setattr__(self, "provider_identity", identity)
        codec = SafeJsonCodec()
        decoded = codec.loads(codec.dumps(dict(configuration)))
        if not isinstance(decoded, Mapping):
            raise TypeError("recovery provider configuration must be a JSON object")
        object.__setattr__(
            self,
            "provider_configuration",
            _freeze_mapping(decoded),
        )


class RecoveryCompensator(Protocol):
    """Optional application interface; never invoked automatically."""

    async def compensate(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: RecoveryExecutionReceipt,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    """An agent- or application-proposed sequence of recovery actions."""

    plan_id: str
    task_id: str
    actions: tuple[RecoveryAction, ...]
    proposed_by: str
    failure_diagnosis: str = "legacy recovery proposal"
    context_reference: str | None = None
    declared_recovery_capability: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW
    approval_required: bool = False
    preconditions: tuple[RecoveryPrecondition, ...] = ()
    postconditions: tuple[RecoveryPostcondition, ...] = ()
    compensation_id: str | None = None
    created_at: datetime = field(default_factory=utc_now)
    plan_hash: str = field(init=False)

    def __post_init__(self) -> None:
        require_non_empty(self.plan_id, "recovery plan id")
        require_non_empty(self.task_id, "recovery plan task_id")
        require_non_empty(self.proposed_by, "recovery plan proposed_by")
        require_non_empty(self.failure_diagnosis, "recovery failure diagnosis")
        require_aware(self.created_at, "recovery plan created_at must be aware")
        if not self.actions:
            raise ValueError("a recovery plan requires at least one action")
        require_unique(
            (action.action_id for action in self.actions),
            "recovery action ids must be unique within a plan",
        )
        preconditions = tuple(self.preconditions)
        postconditions = tuple(self.postconditions)
        require_unique(
            (item.name for item in preconditions),
            "recovery precondition names must be unique",
        )
        require_unique(
            (item.name for item in postconditions),
            "recovery postcondition names must be unique",
        )
        context_reference = self.context_reference or f"task:{self.task_id}"
        declared = self.declared_recovery_capability
        if declared is None and len(self.actions) == 1:
            declared = self.actions[0].capability
        if declared is not None and any(
            item.capability != declared for item in self.actions
        ):
            raise ValueError("declared recovery capability does not match actions")
        snapshot = {
            "plan_id": self.plan_id,
            "task_id": self.task_id,
            "action_hashes": [item.action_hash for item in self.actions],
            "proposed_by": self.proposed_by,
            "failure_diagnosis": self.failure_diagnosis,
            "context_reference": context_reference,
            "declared_recovery_capability": declared,
            "risk_level": self.risk_level.value,
            "approval_required": self.approval_required,
            "preconditions": [
                {
                    "name": item.name,
                    "description": item.description,
                    "evaluator": _callable_identity(item.evaluator),
                }
                for item in preconditions
            ],
            "postconditions": [
                {
                    "name": item.name,
                    "description": item.description,
                    "evidence_type": item.evidence_type,
                    "required": item.required,
                    "provider": (
                        f"{type(item.provider).__module__}."
                        f"{type(item.provider).__qualname__}"
                    ),
                    "provider_acquire": _callable_identity(item.provider.acquire),
                    "provider_identity": item.provider_identity,
                    "provider_configuration": item.provider_configuration,
                }
                for item in postconditions
            ],
            "compensation_id": self.compensation_id,
            "created_at": self.created_at,
        }
        object.__setattr__(self, "context_reference", context_reference)
        object.__setattr__(self, "declared_recovery_capability", declared)
        object.__setattr__(self, "preconditions", preconditions)
        object.__setattr__(self, "postconditions", postconditions)
        object.__setattr__(
            self,
            "plan_hash",
            _sha256(SafeJsonCodec().dumps(snapshot)),
        )


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    """Application-owned allowlist and recovery safety limits."""

    allowed_capabilities: frozenset[str] = field(default_factory=frozenset)
    allowed_task_states: frozenset[TaskStatus] = field(
        default_factory=lambda: frozenset(TaskStatus)
    )
    maximum_risk_level: RiskLevel = RiskLevel.LOW
    approval_required_capabilities: frozenset[str] = field(default_factory=frozenset)
    require_runtime_confirmation: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_capabilities",
            frozenset(self.allowed_capabilities),
        )
        object.__setattr__(
            self,
            "allowed_task_states",
            frozenset(self.allowed_task_states),
        )
        object.__setattr__(
            self,
            "approval_required_capabilities",
            frozenset(self.approval_required_capabilities),
        )

    @classmethod
    def safe_default(cls) -> RecoveryPolicy:
        """Deny every action until an application supplies an explicit policy."""

        return cls()

    @property
    def require_pre_action_confirmation(self) -> bool:
        """Compatibility-safe name for the pre-execution capability gate."""

        return self.require_runtime_confirmation


@dataclass(frozen=True, slots=True)
class PreActionCapabilityConfirmation:
    """Pre-action confirmation that a runtime can safely invoke a capability.

    This is not an executor receipt, external postcondition evidence, or final
    outcome verification. ``RuntimeConfirmation`` remains as a compatibility alias.
    """

    confirmation_id: str
    action_id: str
    capability: str
    idempotency_key: str
    supported: bool
    safe: bool
    confirmed_at: datetime
    confirmed_by: str
    reason: str
    target_hash: str | None = None

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            (
                "confirmation_id",
                "action_id",
                "capability",
                "idempotency_key",
                "confirmed_by",
                "reason",
            ),
            prefix="runtime confirmation",
        )
        require_aware(
            self.confirmed_at,
            "runtime confirmation timestamp must be timezone-aware",
        )


# Compatibility alias. New code should use the semantically precise name above.
RuntimeConfirmation = PreActionCapabilityConfirmation


@dataclass(frozen=True, slots=True)
class RecoveryApproval:
    """Human or policy approval bound to one exact capability action."""

    action_id: str
    capability: str
    idempotency_key: str
    approved: bool
    approved_by: str
    reason: str

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            (
                "action_id",
                "capability",
                "idempotency_key",
                "approved_by",
                "reason",
            ),
            prefix="recovery approval",
        )


@dataclass(frozen=True, slots=True)
class RecoveryReason:
    code: RecoveryReasonCode
    message: str


@dataclass(frozen=True, slots=True)
class RecoveryActionResult:
    action_id: str
    capability: str
    status: RecoveryStatus
    reason: RecoveryReason
    runtime_confirmation: RuntimeConfirmation | None = None
    executor_receipt: RecoveryExecutionReceipt | None = None
    postcondition_evidence: EvidenceCollection = field(
        default_factory=EvidenceCollection
    )
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    plan_id: str
    task_id: str
    status: RecoveryStatus
    actions: tuple[RecoveryActionResult, ...]

    @property
    def executed(self) -> bool:
        return self.status in {
            RecoveryStatus.RUNTIME_CONFIRMED,
            RecoveryStatus.EXECUTING,
            RecoveryStatus.EXECUTOR_SUCCEEDED,
            RecoveryStatus.FAILED,
            RecoveryStatus.UNKNOWN,
            RecoveryStatus.POSTCONDITION_FAILED,
            RecoveryStatus.POSTCONDITIONS_SATISFIED,
            RecoveryStatus.VERIFIED,
        }

    @property
    def succeeded(self) -> bool:
        """Only final outcome verification is durable-recovery success."""

        return self.status is RecoveryStatus.VERIFIED


class RecoveryExecutor(Protocol):
    """Port for policy-gated execution of a proposed recovery plan."""

    async def execute(
        self,
        plan: RecoveryPlan,
        *,
        contract: TaskContract[Any, Any],
        task_state: TaskStatus,
        confirmations: Sequence[RuntimeConfirmation] = (),
        approvals: Sequence[RecoveryApproval] = (),
        dry_run: bool = False,
        correlation_id: str | None = None,
    ) -> RecoveryResult:
        """Evaluate every safety gate before executing any action."""


RecoveryHandler = Callable[
    [RecoveryAction, TaskContract[Any, Any]],
    Awaitable[None],
]

_RISK_ORDER: Mapping[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class InMemoryRecoveryExecutor:
    """Guarded executor with injected handlers and in-memory idempotency state."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        policy: RecoveryPolicy | None = None,
        handlers: Mapping[str, RecoveryHandler] | None = None,
        event_sink: EventSink | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self._registry = registry
        self._policy = policy or RecoveryPolicy.safe_default()
        self._handlers = dict(handlers or {})
        self._event_sink = event_sink or NullEventSink()
        self._clock = clock
        self._executed_keys: set[tuple[str, str]] = set()
        self._in_flight_keys: set[tuple[str, str]] = set()
        self._idempotency_lock = Lock()

    async def execute(
        self,
        plan: RecoveryPlan,
        *,
        contract: TaskContract[Any, Any],
        task_state: TaskStatus,
        confirmations: Sequence[RuntimeConfirmation] = (),
        approvals: Sequence[RecoveryApproval] = (),
        dry_run: bool = False,
        correlation_id: str | None = None,
    ) -> RecoveryResult:
        resolved_correlation_id = correlation_id or plan.plan_id
        sequence = 1
        self._emit_recovery_event(
            LifecycleEventType.RECOVERY_REQUESTED,
            plan=plan,
            task_state=task_state,
            correlation_id=resolved_correlation_id,
            sequence=sequence,
            details={
                "plan_id": plan.plan_id,
                "action_count": len(plan.actions),
                "actions": [
                    {
                        "action_id": action.action_id,
                        "capability": action.capability,
                        "idempotency_key": action.idempotency_key,
                    }
                    for action in plan.actions
                ],
                "dry_run": dry_run,
            },
        )
        if plan.task_id != contract.task_id:
            action = plan.actions[0]
            result = self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.TASK_MISMATCH,
                "recovery plan does not target the supplied task contract",
            )
            recovery_result = RecoveryResult(
                plan_id=plan.plan_id,
                task_id=plan.task_id,
                status=result.status,
                actions=(result,),
            )
            self._emit_recovery_result(
                plan,
                result,
                task_state,
                resolved_correlation_id,
                sequence + 1,
            )
            return recovery_result

        confirmations_by_action = {item.action_id: item for item in confirmations}
        approvals_by_action = {item.action_id: item for item in approvals}
        results: list[RecoveryActionResult] = []
        for action in plan.actions:
            confirmation = confirmations_by_action.get(action.action_id)
            if confirmation is not None:
                sequence += 1
                self._emit_recovery_event(
                    LifecycleEventType.RUNTIME_CONFIRMATION_RECEIVED,
                    plan=plan,
                    task_state=task_state,
                    correlation_id=resolved_correlation_id,
                    sequence=sequence,
                    details={
                        "confirmation_id": confirmation.confirmation_id,
                        "action_id": confirmation.action_id,
                        "capability": confirmation.capability,
                        "idempotency_key": confirmation.idempotency_key,
                        "supported": confirmation.supported,
                        "safe": confirmation.safe,
                        "confirmed_at": confirmation.confirmed_at,
                        "confirmed_by": confirmation.confirmed_by,
                    },
                )
            result = await self._execute_action(
                action,
                contract=contract,
                task_state=task_state,
                confirmation=confirmation,
                approval=approvals_by_action.get(action.action_id),
                dry_run=dry_run,
            )
            results.append(result)
            sequence += 1
            self._emit_recovery_result(
                plan,
                result,
                task_state,
                resolved_correlation_id,
                sequence,
            )
            if result.status not in {
                RecoveryStatus.RUNTIME_CONFIRMED,
                RecoveryStatus.DRY_RUN,
            }:
                break

        overall_status = results[-1].status
        return RecoveryResult(
            plan_id=plan.plan_id,
            task_id=plan.task_id,
            status=overall_status,
            actions=tuple(results),
        )

    def _emit_recovery_result(
        self,
        plan: RecoveryPlan,
        result: RecoveryActionResult,
        task_state: TaskStatus,
        correlation_id: str,
        sequence: int,
    ) -> None:
        event_type = (
            LifecycleEventType.RECOVERY_CONFIRMED
            if result.status is RecoveryStatus.RUNTIME_CONFIRMED
            else LifecycleEventType.RECOVERY_BLOCKED
        )
        self._emit_recovery_event(
            event_type,
            plan=plan,
            task_state=task_state,
            correlation_id=correlation_id,
            sequence=sequence,
            details={
                "action_id": result.action_id,
                "capability": result.capability,
                "status": result.status,
                "reason_code": result.reason.code,
                "reason": result.reason.message,
            },
        )

    def _emit_recovery_event(
        self,
        event_type: LifecycleEventType,
        *,
        plan: RecoveryPlan,
        task_state: TaskStatus,
        correlation_id: str,
        sequence: int,
        details: Mapping[str, Any],
    ) -> None:
        self._event_sink.emit(
            LifecycleEvent(
                event_type=event_type,
                task_id=plan.task_id,
                correlation_id=correlation_id,
                worker_id=plan.proposed_by,
                occurred_at=self._clock(),
                sequence=sequence,
                state=task_state,
                name=event_type.value,
                details=details,
            )
        )

    async def _execute_action(
        self,
        action: RecoveryAction,
        *,
        contract: TaskContract[Any, Any],
        task_state: TaskStatus,
        confirmation: RuntimeConfirmation | None,
        approval: RecoveryApproval | None,
        dry_run: bool,
    ) -> RecoveryActionResult:
        declaration = self._registry.get(action.capability)
        if declaration is None:
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.UNSUPPORTED_CAPABILITY,
                "the runtime has no declaration for this recovery capability",
            )
        blocked = self._check_declaration_and_policy(
            action,
            declaration,
            contract,
            task_state,
        )
        if blocked is not None:
            return blocked

        idempotency_key = (action.capability, action.idempotency_key)
        if self._is_reserved(idempotency_key):
            return self._result(
                action,
                RecoveryStatus.DUPLICATE_PREVENTED,
                RecoveryReasonCode.DUPLICATE_IDEMPOTENCY_KEY,
                "this recovery capability and idempotency key already executed",
            )

        blocked = self._check_approval(action, declaration, approval)
        if blocked is not None:
            return blocked
        blocked = self._check_runtime_confirmation(action, declaration, confirmation)
        if blocked is not None:
            return blocked

        if dry_run:
            return self._result(
                action,
                RecoveryStatus.DRY_RUN,
                RecoveryReasonCode.DRY_RUN_COMPLETE,
                "all recovery gates passed; no action was executed",
                confirmation=confirmation,
            )

        handler = self._handlers.get(action.capability)
        if handler is None:
            return self._result(
                action,
                RecoveryStatus.FAILED,
                RecoveryReasonCode.EXECUTOR_UNAVAILABLE,
                "no local recovery handler is registered for this capability",
                confirmation=confirmation,
            )

        return await self._run_handler(
            action,
            handler,
            idempotency_key,
            contract=contract,
            confirmation=confirmation,
        )

    def _check_approval(
        self,
        action: RecoveryAction,
        declaration: CapabilityDeclaration,
        approval: RecoveryApproval | None,
    ) -> RecoveryActionResult | None:
        """Require an approval bound to this exact action when one is mandated."""

        approval_required = (
            declaration.requires_approval
            or action.capability in self._policy.approval_required_capabilities
        )
        if not approval_required:
            return None
        if approval is None:
            return self._result(
                action,
                RecoveryStatus.APPROVAL_REQUIRED,
                RecoveryReasonCode.APPROVAL_REQUIRED,
                "the recovery action requires explicit approval",
            )
        if not self._valid_approval(action, approval):
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.APPROVAL_REJECTED,
                "the supplied approval does not approve this exact action",
            )
        return None

    def _check_runtime_confirmation(
        self,
        action: RecoveryAction,
        declaration: CapabilityDeclaration,
        confirmation: RuntimeConfirmation | None,
    ) -> RecoveryActionResult | None:
        """Require a runtime confirmation bound to this exact action."""

        confirmation_required = (
            declaration.requires_runtime_confirmation
            or self._policy.require_runtime_confirmation
        )
        if not confirmation_required:
            return None
        if confirmation is None:
            return self._result(
                action,
                RecoveryStatus.AWAITING_RUNTIME_CONFIRMATION,
                RecoveryReasonCode.RUNTIME_CONFIRMATION_REQUIRED,
                "the runtime must confirm capability support and safety",
            )
        if not self._valid_confirmation(action, confirmation):
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.RUNTIME_CONFIRMATION_REJECTED,
                "runtime confirmation was unsafe, unsupported, or mismatched",
                confirmation=confirmation,
            )
        return None

    def _is_reserved(self, idempotency_key: tuple[str, str]) -> bool:
        """Report whether this key already executed or is executing right now."""

        with self._idempotency_lock:
            return (
                idempotency_key in self._executed_keys
                or idempotency_key in self._in_flight_keys
            )

    async def _run_handler(
        self,
        action: RecoveryAction,
        handler: RecoveryHandler,
        idempotency_key: tuple[str, str],
        *,
        contract: TaskContract[Any, Any],
        confirmation: RuntimeConfirmation | None,
    ) -> RecoveryActionResult:
        """Reserve the idempotency key, then run the injected handler once."""

        with self._idempotency_lock:
            if (
                idempotency_key in self._executed_keys
                or idempotency_key in self._in_flight_keys
            ):
                return self._result(
                    action,
                    RecoveryStatus.DUPLICATE_PREVENTED,
                    RecoveryReasonCode.DUPLICATE_IDEMPOTENCY_KEY,
                    "a concurrent recovery already reserved this idempotency key",
                )
            self._in_flight_keys.add(idempotency_key)
        try:
            await handler(action, contract)
        except Exception as error:  # noqa: BLE001 - adapter failures are structured
            return self._result(
                action,
                RecoveryStatus.FAILED,
                RecoveryReasonCode.EXECUTION_FAILED,
                str(error),
                confirmation=confirmation,
                error_type=type(error).__name__,
            )
        finally:
            with self._idempotency_lock:
                self._in_flight_keys.discard(idempotency_key)
        with self._idempotency_lock:
            self._executed_keys.add(idempotency_key)
        return self._result(
            action,
            RecoveryStatus.RUNTIME_CONFIRMED,
            RecoveryReasonCode.EXECUTED,
            "runtime-confirmed recovery executed through the injected handler",
            confirmation=confirmation,
        )

    def _check_declaration_and_policy(
        self,
        action: RecoveryAction,
        declaration: CapabilityDeclaration,
        contract: TaskContract[Any, Any],
        task_state: TaskStatus,
    ) -> RecoveryActionResult | None:
        if not declaration.available:
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.CAPABILITY_UNAVAILABLE,
                "the runtime capability is currently unavailable",
            )
        if not declaration.recovery_supported:
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.RECOVERY_NOT_SUPPORTED,
                "the declaration does not support recovery execution",
            )
        if (
            task_state not in declaration.supported_task_states
            or task_state not in self._policy.allowed_task_states
        ):
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.INVALID_TASK_STATE,
                f"capability is not allowed while the task is {task_state}",
            )
        if action.capability not in self._policy.allowed_capabilities:
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.POLICY_DENIED,
                "recovery policy does not allow this capability",
            )
        task_risk = _risk_rank(contract.risk_level)
        if task_risk > _risk_rank(declaration.maximum_risk_level) or task_risk > (
            _risk_rank(self._policy.maximum_risk_level)
        ):
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.RISK_EXCEEDS_CAPABILITY,
                "task risk exceeds the capability or policy recovery limit",
            )
        if (
            declaration.requires_idempotency
            and action.idempotency_key != contract.idempotency_key
        ):
            return self._result(
                action,
                RecoveryStatus.BLOCKED,
                RecoveryReasonCode.IDEMPOTENCY_MISMATCH,
                "recovery idempotency key does not match the task contract",
            )
        return None

    @staticmethod
    def _valid_approval(
        action: RecoveryAction,
        approval: RecoveryApproval | None,
    ) -> bool:
        return (
            approval is not None
            and approval.action_id == action.action_id
            and approval.capability == action.capability
            and approval.idempotency_key == action.idempotency_key
            and approval.approved
        )

    @staticmethod
    def _valid_confirmation(
        action: RecoveryAction,
        confirmation: RuntimeConfirmation | None,
    ) -> bool:
        return (
            confirmation is not None
            and confirmation.action_id == action.action_id
            and confirmation.capability == action.capability
            and confirmation.idempotency_key == action.idempotency_key
            and confirmation.supported
            and confirmation.safe
        )

    @staticmethod
    def _result(
        action: RecoveryAction,
        status: RecoveryStatus,
        code: RecoveryReasonCode,
        message: str,
        *,
        confirmation: RuntimeConfirmation | None = None,
        error_type: str | None = None,
    ) -> RecoveryActionResult:
        return RecoveryActionResult(
            action_id=action.action_id,
            capability=action.capability,
            status=status,
            reason=RecoveryReason(code=code, message=message),
            runtime_confirmation=confirmation,
            error_type=error_type,
        )


def _risk_rank(risk: RiskLevel) -> int:
    return _RISK_ORDER[risk]


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _callable_identity(value: Callable[..., Any]) -> str:
    module = getattr(value, "__module__", type(value).__module__)
    qualname = getattr(value, "__qualname__", type(value).__qualname__)
    try:
        source = inspect.getsource(value)
    except (OSError, TypeError):
        source = ""
    return f"{module}.{qualname}:{hashlib.sha256(source.encode()).hexdigest()}"


def _stable_provider_configuration(provider: Any) -> Mapping[str, Any]:
    if not is_dataclass(provider) or isinstance(provider, type):
        return {}
    configuration: dict[str, Any] = {}
    for item in fields(provider):
        if not item.compare and item.name != "provider":
            continue
        value = getattr(provider, item.name)
        configuration[item.name] = (
            _callable_identity(value) if callable(value) else value
        )
    encoded = SafeJsonCodec().dumps(configuration)
    decoded = SafeJsonCodec().loads(encoded)
    if not isinstance(decoded, Mapping):
        raise TypeError("recovery provider configuration must be a JSON object")
    return decoded


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if any(not isinstance(key, str) for key in value):
        raise TypeError("recovery configuration keys must be strings")
    return MappingProxyType(
        {key: _freeze_recovery_value(item) for key, item in value.items()}
    )


def _freeze_recovery_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_recovery_value(item) for item in value)
    return value
