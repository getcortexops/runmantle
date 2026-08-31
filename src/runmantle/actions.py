"""Capability-mediated, durable execution boundary for consequential actions."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from ._validation import (
    require_aware,
    require_non_empty,
    require_non_empty_attributes,
    require_unique,
)
from .approvals import ApprovalRequest, StoredApproval
from .capabilities import CapabilityRegistry
from .contracts import RiskLevel, TaskContract, TaskStatus
from .core import CancellationToken, TaskContext
from .evidence import (
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceItem,
    EvidenceProviderRegistry,
    EvidenceTrustLevel,
    _as_agent_claim,
    _establish_evidence_origin,
    new_id,
    utc_now,
)
from .serialization import SafeJsonCodec, SerializationError
from .telemetry import EventSink, LifecycleEvent, LifecycleEventType, NullEventSink

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]

logger = logging.getLogger(__name__)


class ActionExecutionStatus(StrEnum):
    """Durable action state; executor success is deliberately not verification."""

    REQUESTED = "requested"
    POLICY_DECIDED = "policy_decided"
    AWAITING_APPROVAL = "awaiting_approval"
    AUTHORIZED = "authorized"
    BLOCKED = "blocked"
    EXECUTING = "executing"
    EXECUTOR_SUCCEEDED = "executor_succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"
    DRY_RUN = "dry_run"


class ActionPostconditionStatus(StrEnum):
    """Durable evidence-acquisition phase after executor success."""

    NOT_STARTED = "not_started"
    PENDING = "pending"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class ActionConditionResult:
    """One deterministic precondition decision."""

    name: str
    passed: bool
    message: str

    def __post_init__(self) -> None:
        require_non_empty(self.name, "action condition name")
        require_non_empty(self.message, "action condition message")


PreconditionEvaluator = Callable[
    ["ActionRequest"],
    bool | ActionConditionResult,
]


@dataclass(frozen=True, slots=True)
class Precondition:
    """Application-supplied check evaluated before authorization."""

    name: str
    description: str
    evaluator: PreconditionEvaluator = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "precondition name")
        require_non_empty(self.description, "precondition description")
        if not callable(self.evaluator):
            raise TypeError("precondition evaluator must be callable")

    def evaluate(self, request: ActionRequest) -> ActionConditionResult:
        result = self.evaluator(request)
        if isinstance(result, ActionConditionResult):
            return result
        return ActionConditionResult(
            name=self.name,
            passed=bool(result),
            message=(
                "precondition satisfied" if result else "precondition was not satisfied"
            ),
        )


class ActionEvidenceProvider(Protocol):
    """Acquire postcondition evidence after an executor returns a receipt."""

    async def acquire(
        self,
        request: ActionRequest,
        receipt: ActionReceipt,
    ) -> EvidenceItem | EvidenceCollection | Sequence[EvidenceItem]:
        """Acquire evidence without treating the receipt as independent proof."""


@dataclass(frozen=True, slots=True)
class Postcondition:
    """Evidence acquisition required after an executor-reported success."""

    name: str
    description: str
    provider: ActionEvidenceProvider = field(compare=False, repr=False)
    evidence_type: str | None = None
    required: bool = True
    provider_identity: str | None = None
    provider_configuration: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "postcondition name")
        require_non_empty(self.description, "postcondition description")
        if not callable(getattr(self.provider, "acquire", None)):
            raise TypeError("postcondition provider must implement acquire")
        if self.evidence_type is not None:
            require_non_empty(self.evidence_type, "postcondition evidence_type")
        identity = self.provider_identity or callable_semantic_identity(
            self.provider.acquire
        )
        require_non_empty(identity, "postcondition provider_identity")
        configuration = (
            self.provider_configuration
            if self.provider_configuration
            else _stable_provider_configuration(self.provider)
        )
        object.__setattr__(self, "provider_identity", identity)
        object.__setattr__(
            self,
            "provider_configuration",
            _freeze_mapping(configuration),
        )


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """Agent claim proposing one exact capability-bound action."""

    action_id: str
    task_id: str
    name: str
    required_capability: str
    input: Mapping[str, Any]
    idempotency_key: str
    risk_level: RiskLevel
    requested_by: str
    requested_at: datetime
    execution_handler_id: str = "application.handler.unspecified"
    timeout: timedelta = timedelta(seconds=30)
    preconditions: tuple[Precondition, ...] = ()
    postconditions: tuple[Postcondition, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    input_hash: str = field(init=False)
    action_hash: str = field(init=False)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            (
                "action_id",
                "task_id",
                "name",
                "required_capability",
                "idempotency_key",
                "requested_by",
                "execution_handler_id",
            ),
            prefix="action request",
        )
        require_aware(
            self.requested_at,
            "action request timestamp must be timezone-aware",
        )
        if self.timeout.total_seconds() <= 0:
            raise ValueError("action timeout must be greater than zero")
        preconditions = tuple(self.preconditions)
        postconditions = tuple(self.postconditions)
        require_unique(
            (item.name for item in preconditions),
            "precondition names must be unique",
        )
        require_unique(
            (item.name for item in postconditions),
            "postcondition names must be unique",
        )
        frozen_input = _freeze_mapping(self.input)
        frozen_metadata = _freeze_mapping(self.metadata)
        codec = SafeJsonCodec()
        encoded_input = codec.dumps(frozen_input)
        input_hash = _sha256(encoded_input)
        approval_manifest = {
            "manifest_version": 2,
            "task_id": self.task_id,
            "name": self.name,
            "required_capability": self.required_capability,
            "input_hash": input_hash,
            "idempotency_key": self.idempotency_key,
            "risk_level": self.risk_level.value,
            "requested_by": self.requested_by,
            "execution_handler_id": self.execution_handler_id,
            "metadata": frozen_metadata,
            "timeout_seconds": self.timeout.total_seconds(),
            "preconditions": [
                {
                    "name": item.name,
                    "description": item.description,
                    "evaluator": callable_semantic_identity(item.evaluator),
                }
                for item in self.preconditions
            ],
            "postconditions": [
                {
                    "name": item.name,
                    "description": item.description,
                    "evidence_type": item.evidence_type,
                    "required": item.required,
                    "provider_identity": item.provider_identity,
                    "provider_configuration": item.provider_configuration,
                }
                for item in self.postconditions
            ],
        }
        action_hash = _sha256(codec.dumps(approval_manifest))
        object.__setattr__(self, "input", frozen_input)
        object.__setattr__(self, "metadata", frozen_metadata)
        object.__setattr__(self, "preconditions", preconditions)
        object.__setattr__(self, "postconditions", postconditions)
        object.__setattr__(self, "input_hash", input_hash)
        object.__setattr__(self, "action_hash", action_hash)

    @property
    def approval_manifest(self) -> Mapping[str, Any]:
        """Canonical security-relevant manifest represented by ``action_hash``."""

        return MappingProxyType(
            {
                "manifest_version": 2,
                "task_id": self.task_id,
                "name": self.name,
                "required_capability": self.required_capability,
                "input_hash": self.input_hash,
                "idempotency_key": self.idempotency_key,
                "risk_level": self.risk_level.value,
                "requested_by": self.requested_by,
                "execution_handler_id": self.execution_handler_id,
                "metadata": self.metadata,
                "timeout_seconds": self.timeout.total_seconds(),
                "preconditions": tuple(
                    {
                        "name": item.name,
                        "description": item.description,
                        "evaluator": callable_semantic_identity(item.evaluator),
                    }
                    for item in self.preconditions
                ),
                "postconditions": tuple(
                    {
                        "name": item.name,
                        "description": item.description,
                        "evidence_type": item.evidence_type,
                        "required": item.required,
                        "provider_identity": item.provider_identity,
                        "provider_configuration": item.provider_configuration,
                    }
                    for item in self.postconditions
                ),
            }
        )

    @property
    def approval_key(self) -> str:
        """Stable key applications use for an exact pre-action approval."""

        return f"action:{self.action_hash}"

    @property
    def approval_scope(self) -> str:
        """Scope that an approval must grant for this capability invocation."""

        return f"capability:{self.required_capability}:execute"

    @property
    def approval_id(self) -> str:
        """Stable identifier for the durable pre-action approval record."""

        return f"action:{self.action_id}:approval"


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    """Application-owned allowlist evaluated before action authorization."""

    allowed_capabilities: frozenset[str] = field(default_factory=frozenset)
    allowed_task_states: frozenset[TaskStatus] = field(
        default_factory=lambda: frozenset({TaskStatus.RUNNING})
    )
    maximum_risk_level: RiskLevel = RiskLevel.LOW
    approval_required_capabilities: frozenset[str] = field(default_factory=frozenset)

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
    def safe_default(cls) -> ActionPolicy:
        """Deny every action until the application supplies an allowlist."""

        return cls()


@dataclass(frozen=True, slots=True)
class ActionPolicyDecision:
    """Persisted policy decision, separate from an agent request."""

    allowed: bool
    reasons: tuple[str, ...]
    requires_approval: bool
    decided_at: datetime
    decided_by: str = "runmantle.action_policy"

    def __post_init__(self) -> None:
        require_aware(self.decided_at, "policy decision timestamp must be aware")
        require_non_empty(self.decided_by, "policy decision decided_by")
        if not self.reasons:
            raise ValueError("policy decision requires at least one reason")


@dataclass(frozen=True, slots=True)
class PreActionAuthorization:
    """Runtime authorization made after policy and precondition evaluation."""

    authorized: bool
    reason: str
    evaluated_preconditions: tuple[ActionConditionResult, ...]
    approved_by: str | None
    authorized_at: datetime
    awaiting_approval: bool = False

    def __post_init__(self) -> None:
        require_non_empty(self.reason, "pre-action authorization reason")
        require_aware(
            self.authorized_at,
            "pre-action authorization timestamp must be aware",
        )


@dataclass(frozen=True, slots=True)
class ExecutorResult:
    """Explicit result returned by an action handler."""

    succeeded: bool
    output: Any = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    """Executor-reported receipt; it is not independent outcome evidence."""

    receipt_id: str
    action_id: str
    executor_id: str
    status: ActionExecutionStatus
    action_hash: str
    input_hash: str
    idempotency_key: str
    started_at: datetime
    finished_at: datetime
    output: Any = None
    message: str = ""
    error_type: str | None = None
    output_hash: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            (
                "receipt_id",
                "action_id",
                "executor_id",
                "action_hash",
                "input_hash",
                "idempotency_key",
            ),
            prefix="action receipt",
        )
        require_aware(self.started_at, "action receipt started_at must be aware")
        require_aware(self.finished_at, "action receipt finished_at must be aware")
        if self.finished_at < self.started_at:
            raise ValueError("action receipt cannot finish before it starts")
        if self.status not in {
            ActionExecutionStatus.EXECUTOR_SUCCEEDED,
            ActionExecutionStatus.FAILED,
            ActionExecutionStatus.UNKNOWN,
            ActionExecutionStatus.CANCELLED,
            ActionExecutionStatus.DRY_RUN,
        }:
            raise ValueError("action receipt requires an executor terminal status")
        if self.output is not None:
            encoded = SafeJsonCodec().dumps(self.output)
            object.__setattr__(self, "output_hash", _sha256(encoded))


class PostActionRuntimeConfirmationStatus(StrEnum):
    """Result of an independent observation made after an action ran."""

    CONFIRMED = "confirmed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    AWAITING_EVIDENCE = "awaiting_evidence"


@dataclass(frozen=True, slots=True)
class PostActionRuntimeConfirmation:
    """Independent target-state observation, deliberately separate from a receipt.

    The provider which creates this object is expected to query the target (for
    example ``/health`` or ``/version``).  A handler report or ``ActionReceipt``
    alone is never a valid confirmation.
    """

    confirmation_id: str
    task_id: str
    action_id: str
    action_hash: str
    receipt_id: str
    status: PostActionRuntimeConfirmationStatus
    provider_id: str
    observed_state: Mapping[str, Any]
    expected_state: Mapping[str, Any]
    evidence: EvidenceCollection
    checked_at: datetime
    actor: str

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            (
                "confirmation_id",
                "task_id",
                "action_id",
                "action_hash",
                "receipt_id",
                "provider_id",
                "actor",
            ),
            prefix="post-action runtime confirmation",
        )
        require_aware(
            self.checked_at, "post-action confirmation timestamp must be aware"
        )
        object.__setattr__(self, "observed_state", _freeze_mapping(self.observed_state))
        object.__setattr__(self, "expected_state", _freeze_mapping(self.expected_state))


class PostActionRuntimeConfirmationProvider(Protocol):
    """Adapter port for observing a target after a mediated action completes."""

    async def confirm(
        self, request: ActionRequest, receipt: ActionReceipt
    ) -> PostActionRuntimeConfirmation: ...


@dataclass(frozen=True, slots=True)
class StoredAction:
    """Authoritative durable action snapshot."""

    action_id: str
    task_id: str
    name: str
    required_capability: str
    input: Mapping[str, Any]
    input_hash: str
    action_hash: str
    idempotency_key: str
    risk_level: RiskLevel
    requested_by: str
    requested_at: datetime
    timeout: timedelta
    dry_run: bool
    status: ActionExecutionStatus
    policy_decision: ActionPolicyDecision | None
    authorization: PreActionAuthorization | None
    receipt: ActionReceipt | None
    postcondition_status: ActionPostconditionStatus
    policy_task_context_version: int | None
    execution_owner_id: str | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ActionExecutionResult:
    """Mediated result with receipt and postcondition evidence kept distinct."""

    action: StoredAction
    outcome_evidence: EvidenceCollection = field(default_factory=EvidenceCollection)
    postcondition_errors: tuple[str, ...] = ()
    duplicate_prevented: bool = False
    post_action_confirmation: PostActionRuntimeConfirmation | None = None

    @property
    def executor_succeeded(self) -> bool:
        return self.action.status is ActionExecutionStatus.EXECUTOR_SUCCEEDED

    @property
    def verified_outcome(self) -> bool:
        """Never infer verification from an executor receipt."""

        return False


class RequiredPostconditionError(RuntimeError):
    """A required postcondition failed to produce usable outcome evidence."""


ActionHandler = Callable[
    [Mapping[str, Any], CancellationToken],
    Awaitable[ExecutorResult | Any],
]


class ActionStore(Protocol):
    """Persistence operations required by ``MediatedActionExecutor``."""

    def validate_contract(
        self,
        task_id: str,
        contract: TaskContract[Any, Any],
    ) -> None: ...

    def load_task(self, task_id: str) -> Any: ...

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

    def approval_values(
        self,
        task_id: str,
        *,
        occurred_at: datetime | None = None,
    ) -> dict[str, bool]: ...

    def request_approval(
        self,
        task_id: str,
        *,
        approval_id: str,
        approval_key: str,
        reason: str,
        occurred_at: datetime,
    ) -> tuple[Any, LifecycleEvent | None]: ...

    def create_approval_request(
        self,
        request: ApprovalRequest,
    ) -> tuple[StoredApproval, LifecycleEvent | None]: ...

    def find_approval(
        self,
        task_id: str,
        *,
        target_hash: str,
        required_scope: str,
        occurred_at: datetime,
    ) -> StoredApproval | None: ...

    def load_approval(self, approval_id: str) -> StoredApproval: ...

    def record_evidence(
        self,
        task_id: str,
        item: EvidenceItem,
    ) -> tuple[EvidenceItem, LifecycleEvent | None]: ...

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


class ActionExecutor(Protocol):
    """Mediated port through which supported consequential actions execute."""

    async def execute(
        self,
        request: ActionRequest,
        *,
        contract: TaskContract[Any, Any],
        handler: ActionHandler,
        granted_capabilities: frozenset[str] | None = None,
        cancellation: CancellationToken | None = None,
        dry_run: bool = False,
    ) -> ActionExecutionResult: ...


class MediatedActionExecutor:
    """Fail-closed durable executor with policy, authorization, and evidence gates."""

    def __init__(
        self,
        *,
        store: ActionStore,
        capabilities: CapabilityRegistry | None = None,
        policy: ActionPolicy | None = None,
        event_sink: EventSink | None = None,
        executor_id: str = "runmantle.local_action_executor",
        instance_id: str | None = None,
        clock: Clock = utc_now,
        id_factory: IdFactory = new_id,
        evidence_providers: EvidenceProviderRegistry | None = None,
    ) -> None:
        require_non_empty(executor_id, "action executor_id")
        self.store = store
        self.capabilities = capabilities or CapabilityRegistry()
        self.policy = policy or ActionPolicy.safe_default()
        self.event_sink = event_sink or NullEventSink()
        self.executor_id = executor_id
        self.instance_id = instance_id or new_id()
        self.clock = clock
        self.id_factory = id_factory
        self.evidence_providers = evidence_providers or EvidenceProviderRegistry()
        self.evidence_providers.seal()

    async def execute(
        self,
        request: ActionRequest,
        *,
        contract: TaskContract[Any, Any],
        handler: ActionHandler,
        granted_capabilities: frozenset[str] | None = None,
        cancellation: CancellationToken | None = None,
        dry_run: bool = False,
    ) -> ActionExecutionResult:
        if request.task_id != contract.task_id:
            raise ValueError("action request task does not match its contract")
        self.store.validate_contract(request.task_id, contract)
        action, created, event = self.store.prepare_action(
            request,
            dry_run=dry_run,
            occurred_at=self.clock(),
        )
        self._publish_optional(event)
        if not created and action.status is ActionExecutionStatus.EXECUTING:
            if action.execution_owner_id != self.instance_id:
                action, unknown_event = self.store.mark_action_unknown(
                    action.action_id,
                    expected_version=action.version,
                    occurred_at=self.clock(),
                    reason="a prior executor instance stopped after execution began",
                )
                self._publish(unknown_event)
            return self._duplicate_result(action)
        if (
            not created
            and action.status is ActionExecutionStatus.EXECUTOR_SUCCEEDED
            and action.postcondition_status is ActionPostconditionStatus.PENDING
        ):
            return await self._acquire_postconditions(
                request,
                action,
                duplicate=True,
            )
        if not created and action.status in _ACTION_TERMINAL_STATES:
            return self._duplicate_result(action)

        if action.status is ActionExecutionStatus.AWAITING_APPROVAL:
            approval = self._active_approval(request)
            if (
                approval is None
                and self.store.approval_values(
                    request.task_id,
                    occurred_at=self.clock(),
                ).get(request.approval_key)
                is not False
            ):
                self._ensure_approval_request(request)
                return self._duplicate_result(action)

        if action.status is ActionExecutionStatus.REQUESTED:
            task = self.store.load_task(request.task_id)
            decision = self._decide_policy(
                request,
                contract=contract,
                task_state=task.status,
                granted_capabilities=(
                    contract.allowed_capabilities
                    if granted_capabilities is None
                    else granted_capabilities
                ),
            )
            action, policy_event = self.store.record_action_policy(
                action.action_id,
                expected_version=action.version,
                decision=decision,
            )
            self._publish(policy_event)

        if action.status in {
            ActionExecutionStatus.POLICY_DECIDED,
            ActionExecutionStatus.AWAITING_APPROVAL,
        }:
            persisted_decision = action.policy_decision
            assert persisted_decision is not None
            authorization = self._authorize(request, persisted_decision)
            action, authorization_event = self.store.record_action_authorization(
                action.action_id,
                expected_version=action.version,
                authorization=authorization,
            )
            self._publish(authorization_event)
            if authorization.awaiting_approval:
                self._ensure_approval_request(request)
        if action.status is ActionExecutionStatus.BLOCKED:
            return self._result(action)
        if action.status is ActionExecutionStatus.AWAITING_APPROVAL:
            return self._result(action)

        token = cancellation or CancellationToken()
        if token.is_cancelled:
            receipt = self._receipt(
                request,
                status=ActionExecutionStatus.CANCELLED,
                started_at=self.clock(),
                message="action cancellation was requested before execution",
            )
            action, finish_event = self.store.finish_action(
                action.action_id,
                expected_version=action.version,
                receipt=receipt,
            )
            self._publish(finish_event)
            return self._result(action)
        if dry_run:
            receipt = self._receipt(
                request,
                status=ActionExecutionStatus.DRY_RUN,
                started_at=self.clock(),
                message="authorization succeeded; handler was not invoked",
            )
            action, finish_event = self.store.finish_action(
                action.action_id,
                expected_version=action.version,
                receipt=receipt,
            )
            self._publish(finish_event)
            return self._result(action)

        started_at = self.clock()
        approval = (
            self._active_approval(request)
            if action.policy_decision is not None
            and action.policy_decision.requires_approval
            else None
        )
        if (
            action.policy_decision is not None
            and action.policy_decision.requires_approval
        ):
            if approval is None:
                return self._result(action)
        action, started_event = self.store.mark_action_executing(
            action.action_id,
            expected_version=action.version,
            occurred_at=started_at,
            owner_id=self.instance_id,
            approval_id=(None if approval is None else approval.request.approval_id),
            approval_request_hash=(
                None if approval is None else approval.request.request_hash
            ),
            approval_scope=request.approval_scope if approval is not None else None,
        )
        self._publish(started_event)
        try:
            executor_result = await self._execute_with_guards(
                handler(request.input, token),
                timeout_seconds=request.timeout.total_seconds(),
                cancellation=token,
            )
            if not isinstance(executor_result, ExecutorResult):
                executor_result = ExecutorResult(succeeded=True, output=executor_result)
            receipt = self._receipt(
                request,
                status=(
                    ActionExecutionStatus.EXECUTOR_SUCCEEDED
                    if executor_result.succeeded
                    else ActionExecutionStatus.FAILED
                ),
                started_at=started_at,
                output=executor_result.output,
                message=executor_result.message,
            )
        except (_ActionInterrupted, asyncio.CancelledError) as error:
            receipt = self._receipt(
                request,
                status=ActionExecutionStatus.UNKNOWN,
                started_at=started_at,
                message=str(error) or "execution was interrupted",
                error_type=type(error).__name__,
            )
        except Exception as error:  # noqa: BLE001 - partial side effects are unknown
            receipt = self._receipt(
                request,
                status=ActionExecutionStatus.UNKNOWN,
                started_at=started_at,
                message=str(error),
                error_type=type(error).__name__,
            )

        try:
            action, finish_event = self.store.finish_action(
                action.action_id,
                expected_version=action.version,
                receipt=receipt,
            )
        except SerializationError:
            action, finish_event = self.store.mark_action_unknown(
                action.action_id,
                expected_version=action.version,
                occurred_at=self.clock(),
                reason="executor output could not be safely persisted",
            )
        self._publish(finish_event)
        if action.status is not ActionExecutionStatus.EXECUTOR_SUCCEEDED:
            return self._result(action)
        return await self._acquire_postconditions(request, action)

    def _decide_policy(
        self,
        request: ActionRequest,
        *,
        contract: TaskContract[Any, Any],
        task_state: TaskStatus,
        granted_capabilities: frozenset[str],
    ) -> ActionPolicyDecision:
        reasons: list[str] = []
        declaration = self.capabilities.get(request.required_capability)
        if request.required_capability not in contract.allowed_capabilities:
            reasons.append("required capability is absent from the task contract")
        if request.required_capability not in granted_capabilities:
            reasons.append("required capability was not granted to the caller")
        if declaration is None:
            reasons.append("required capability is not registered")
        elif not declaration.available:
            reasons.append("required capability is unavailable")
        if request.required_capability not in self.policy.allowed_capabilities:
            reasons.append("action policy does not allow the required capability")
        if task_state not in self.policy.allowed_task_states:
            reasons.append(
                f"action policy does not allow task state {task_state.value}"
            )
        if (
            declaration is not None
            and task_state not in declaration.supported_task_states
        ):
            reasons.append("capability does not support the current task state")
        if _risk_rank(request.risk_level) > _risk_rank(self.policy.maximum_risk_level):
            reasons.append("action risk exceeds policy maximum")
        if declaration is not None and _risk_rank(request.risk_level) > _risk_rank(
            declaration.maximum_risk_level
        ):
            reasons.append("action risk exceeds capability maximum")
        requires_approval = (
            request.required_capability in self.policy.approval_required_capabilities
            or (declaration is not None and declaration.requires_approval)
        )
        return ActionPolicyDecision(
            allowed=not reasons,
            reasons=tuple(reasons or ("all capability and policy checks passed",)),
            requires_approval=requires_approval,
            decided_at=self.clock(),
        )

    def _authorize(
        self,
        request: ActionRequest,
        decision: ActionPolicyDecision,
    ) -> PreActionAuthorization:
        evaluated: list[ActionConditionResult] = []
        if decision.allowed:
            for precondition in request.preconditions:
                try:
                    evaluated.append(precondition.evaluate(request))
                except Exception as error:  # noqa: BLE001 - fail closed
                    evaluated.append(
                        ActionConditionResult(
                            name=precondition.name,
                            passed=False,
                            message=(
                                f"precondition raised {type(error).__name__}: {error}"
                            ),
                        )
                    )
        stored_approval = self._active_approval(request)
        approval = stored_approval is not None
        rejected = (
            self.store.approval_values(
                request.task_id,
                occurred_at=self.clock(),
            ).get(request.approval_key)
            is False
        )
        authorized = (
            decision.allowed
            and all(item.passed for item in evaluated)
            and (not decision.requires_approval or approval)
        )
        if not decision.allowed:
            reason = "; ".join(decision.reasons)
        elif any(not item.passed for item in evaluated):
            reason = "one or more preconditions failed"
        elif decision.requires_approval and not approval:
            reason = (
                "exact action approval was rejected"
                if rejected
                else f"approval {request.approval_key!r} is required"
            )
        else:
            reason = "policy, capability, approval, and precondition checks passed"
        return PreActionAuthorization(
            authorized=authorized,
            reason=reason,
            evaluated_preconditions=tuple(evaluated),
            approved_by=(
                stored_approval.decision.approver.subject
                if stored_approval is not None and stored_approval.decision is not None
                else None
            ),
            authorized_at=self.clock(),
            awaiting_approval=(
                decision.allowed
                and all(item.passed for item in evaluated)
                and decision.requires_approval
                and not approval
                and not rejected
            ),
        )

    async def _acquire_postconditions(
        self,
        request: ActionRequest,
        action: StoredAction,
        *,
        duplicate: bool = False,
    ) -> ActionExecutionResult:
        receipt = action.receipt
        assert receipt is not None
        errors: list[str] = []
        required_errors: list[str] = []
        completed = self.store.completed_action_postconditions(action.action_id)
        for postcondition in request.postconditions:
            if postcondition.name in completed:
                continue
            try:
                acquired = await postcondition.provider.acquire(request, receipt)
                items = tuple(
                    self._establish_provider_evidence(postcondition, item)
                    for item in _evidence_items(acquired)
                )
                if postcondition.required and not items:
                    raise ValueError("required provider returned no outcome evidence")
                if postcondition.evidence_type is not None and any(
                    item.type != postcondition.evidence_type for item in items
                ):
                    raise ValueError("provider returned the wrong evidence type")
                events = self.store.complete_action_postcondition(
                    action.action_id,
                    postcondition_name=postcondition.name,
                    items=items,
                    occurred_at=self.clock(),
                )
                for event in events:
                    self._publish(event)
            except Exception as error:  # noqa: BLE001 - evidence failure is explicit
                message = (
                    f"postcondition {postcondition.name!r} failed: "
                    f"{type(error).__name__}: {error}"
                )
                errors.append(message)
                if postcondition.required:
                    required_errors.append(message)
                failure_event = self.store.append_event(
                    request.task_id,
                    event_type=LifecycleEventType.ACTION_POSTCONDITION_FAILED,
                    occurred_at=self.clock(),
                    name="action.postcondition_failed",
                    details={
                        "action_id": action.action_id,
                        "postcondition": postcondition.name,
                        "required": postcondition.required,
                        "error_type": type(error).__name__,
                    },
                    dedupe_key=(
                        f"action:{action.action_id}:postcondition:"
                        f"{postcondition.name}:failed"
                    ),
                )
                self._publish(failure_event)
        if required_errors:
            raise RequiredPostconditionError("; ".join(required_errors))
        action, completed_event = self.store.complete_action_postconditions(
            action.action_id,
            expected_version=self.store.load_action(action.action_id).version,
            occurred_at=self.clock(),
        )
        self._publish(completed_event)
        return ActionExecutionResult(
            action=action,
            outcome_evidence=self.store.action_evidence(action.action_id),
            postcondition_errors=tuple(errors),
            duplicate_prevented=duplicate,
        )

    def _establish_provider_evidence(
        self,
        postcondition: Postcondition,
        item: EvidenceItem,
    ) -> EvidenceItem:
        assert postcondition.provider_identity is not None
        established = self.evidence_providers._establish(
            postcondition.provider,
            item,
            boundary="mediated_action_postcondition",
            provider_identity=postcondition.provider_identity,
            provider_configuration=postcondition.provider_configuration,
        )
        if established is not None:
            return established

        # Delayed import avoids the provider module's dependency on action types.
        from .evidence_providers import (
            ActionReceiptEvidenceProvider,
            FileEvidenceProvider,
        )

        if type(postcondition.provider) is ActionReceiptEvidenceProvider:
            trust_level = EvidenceTrustLevel.EXECUTOR_RECEIPT
            acquisition_method = EvidenceAcquisitionMethod.EXECUTOR_REPORTED
        elif type(postcondition.provider) is FileEvidenceProvider:
            trust_level = EvidenceTrustLevel.RUNTIME_OBSERVED
            acquisition_method = EvidenceAcquisitionMethod.FILESYSTEM_INSPECTION
        else:
            return _as_agent_claim(item)
        return _establish_evidence_origin(
            item,
            boundary="mediated_action_postcondition",
            provider_identity=postcondition.provider_identity,
            provider_configuration=postcondition.provider_configuration,
            trust_level=trust_level,
            acquisition_method=acquisition_method,
        )

    async def _execute_with_guards(
        self,
        operation: Awaitable[ExecutorResult | Any],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> ExecutorResult | Any:
        action_task = asyncio.ensure_future(operation)
        cancellation_waiter = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {action_task, cancellation_waiter},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if action_task in done:
                return await action_task
            action_task.cancel()
            await _suppress_cancelled(action_task)
            if cancellation_waiter in done:
                raise _ActionInterrupted("action cancellation interrupted execution")
            raise _ActionInterrupted("action timeout interrupted execution")
        finally:
            if not action_task.done():
                action_task.cancel()
                await _suppress_cancelled(action_task)
            if not cancellation_waiter.done():
                cancellation_waiter.cancel()
                await _suppress_cancelled(cancellation_waiter)

    def _receipt(
        self,
        request: ActionRequest,
        *,
        status: ActionExecutionStatus,
        started_at: datetime,
        output: Any = None,
        message: str = "",
        error_type: str | None = None,
    ) -> ActionReceipt:
        return ActionReceipt(
            receipt_id=self.id_factory(),
            action_id=request.action_id,
            executor_id=self.executor_id,
            status=status,
            action_hash=request.action_hash,
            input_hash=request.input_hash,
            idempotency_key=request.idempotency_key,
            started_at=started_at,
            finished_at=self.clock(),
            output=output,
            message=message,
            error_type=error_type,
        )

    def _result(
        self,
        action: StoredAction,
        *,
        duplicate: bool = False,
    ) -> ActionExecutionResult:
        return ActionExecutionResult(
            action=action,
            outcome_evidence=self.store.action_evidence(action.action_id),
            duplicate_prevented=duplicate,
        )

    def _duplicate_result(self, action: StoredAction) -> ActionExecutionResult:
        event = self.store.append_event(
            action.task_id,
            event_type=LifecycleEventType.ACTION_DUPLICATE_PREVENTED,
            occurred_at=self.clock(),
            name="action.duplicate_prevented",
            details={
                "action_id": action.action_id,
                "execution_status": action.status,
                "idempotency_key": action.idempotency_key,
            },
            dedupe_key=f"action:{action.action_id}:duplicate-prevented",
        )
        self._publish(event)
        return self._result(action, duplicate=True)

    def _ensure_approval_request(self, request: ActionRequest) -> None:
        if request.execution_handler_id == "application.handler.unspecified":
            raise ValueError(
                "approval-bound actions require an explicit stable execution_handler_id"
            )
        approval = ApprovalRequest(
            approval_id=request.approval_id,
            task_id=request.task_id,
            target_id=request.action_id,
            target_hash=request.approval_key,
            required_scope=request.approval_scope,
            risk_level=request.risk_level,
            reason=(
                f"Authorize mediated action {request.name!r} with hash "
                f"{request.action_hash}."
            ),
            created_at=request.requested_at,
            expires_at=request.requested_at + timedelta(days=1),
            one_time_use=True,
            metadata={
                "action_hash": request.action_hash,
                "input_hash": request.input_hash,
                "capability": request.required_capability,
                "idempotency_key": request.idempotency_key,
                "approval_manifest": request.approval_manifest,
            },
        )
        _, event = self.store.create_approval_request(approval)
        self._publish_optional(event)

    def _active_approval(self, request: ActionRequest) -> StoredApproval | None:
        return self.store.find_approval(
            request.task_id,
            target_hash=request.approval_key,
            required_scope=request.approval_scope,
            occurred_at=self.clock(),
        )

    def _publish_optional(self, event: LifecycleEvent | None) -> None:
        if event is not None:
            self._publish(event)

    def _publish(self, event: LifecycleEvent) -> None:
        try:
            self.event_sink.emit(event)
        except Exception:
            # The durable store remains authoritative after its transaction commits.
            logger.warning(
                "external action event sink failed after durable event commit",
                exc_info=True,
            )


FunctionToolCallable = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class SafeFunctionTool:
    """Wrap a Python function so supported calls cross the mediated boundary."""

    name: str
    description: str
    required_capability: str
    function: FunctionToolCallable = field(compare=False, repr=False)
    executor: ActionExecutor = field(compare=False, repr=False)
    risk_level: RiskLevel = RiskLevel.LOW
    timeout: timedelta = timedelta(seconds=30)
    preconditions: tuple[Precondition, ...] = ()
    postconditions: tuple[Postcondition, ...] = ()
    clock: Clock = field(default=utc_now, compare=False, repr=False)
    id_factory: IdFactory = field(default=new_id, compare=False, repr=False)

    def __post_init__(self) -> None:
        require_non_empty(self.name, "function tool name")
        require_non_empty(self.description, "function tool description")
        require_non_empty(self.required_capability, "function tool capability")
        if not callable(self.function):
            raise TypeError("function tool requires a callable")

    async def invoke(
        self,
        *,
        contract: TaskContract[Any, Any],
        context: TaskContext,
        arguments: Mapping[str, Any],
        idempotency_key: str,
        action_id: str | None = None,
        requested_by: str = "worker",
        dry_run: bool = False,
    ) -> ActionExecutionResult:
        request = ActionRequest(
            action_id=action_id or self.id_factory(),
            task_id=contract.task_id,
            name=self.name,
            required_capability=self.required_capability,
            input=arguments,
            idempotency_key=idempotency_key,
            risk_level=self.risk_level,
            requested_by=requested_by,
            requested_at=self.clock(),
            execution_handler_id=callable_semantic_identity(self.function),
            timeout=self.timeout,
            preconditions=self.preconditions,
            postconditions=self.postconditions,
        )

        async def handler(
            action_input: Mapping[str, Any],
            cancellation: CancellationToken,
        ) -> Any:
            cancellation.raise_if_cancelled()
            if inspect.iscoroutinefunction(self.function):
                return await self.function(**dict(action_input))
            result = await asyncio.to_thread(self.function, **dict(action_input))
            if inspect.isawaitable(result):
                return await result
            return result

        return await self.executor.execute(
            request,
            contract=contract,
            handler=handler,
            granted_capabilities=context.allowed_capabilities,
            cancellation=context.cancellation,
            dry_run=dry_run,
        )


class _ActionInterrupted(RuntimeError):
    pass


_ACTION_TERMINAL_STATES = frozenset(
    {
        ActionExecutionStatus.BLOCKED,
        ActionExecutionStatus.EXECUTOR_SUCCEEDED,
        ActionExecutionStatus.FAILED,
        ActionExecutionStatus.UNKNOWN,
        ActionExecutionStatus.CANCELLED,
        ActionExecutionStatus.DRY_RUN,
    }
)


async def _suppress_cancelled(task: asyncio.Future[Any]) -> None:
    try:
        await task
    except asyncio.CancelledError:
        pass


def _risk_rank(level: RiskLevel) -> int:
    return {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
    }[level]


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def callable_semantic_identity(value: Callable[..., Any]) -> str:
    """Return a stable code identity without process-local object addresses."""

    module = getattr(value, "__module__", type(value).__module__)
    qualname = getattr(value, "__qualname__", type(value).__qualname__)
    try:
        source = inspect.getsource(value)
    except (OSError, TypeError):
        source = ""
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return f"{module}.{qualname}:sha256:{digest}"


def _stable_provider_configuration(provider: Any) -> Mapping[str, Any]:
    """Derive stable dataclass configuration without process-local repr values."""

    if not is_dataclass(provider) or isinstance(provider, type):
        return {}
    configuration: dict[str, Any] = {}
    for item in fields(provider):
        if not item.compare and item.name != "provider":
            continue
        value = getattr(provider, item.name)
        if callable(value):
            configuration[item.name] = callable_semantic_identity(value)
        else:
            configuration[item.name] = value
    encoded = SafeJsonCodec().dumps(configuration)
    decoded = SafeJsonCodec().loads(encoded)
    if not isinstance(decoded, Mapping):
        raise TypeError("postcondition provider configuration must be a JSON object")
    return decoded


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if any(not isinstance(key, str) for key in value):
        raise SerializationError("action input keys must be strings")
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)
    if isinstance(value, Path):
        return value
    return value


def _evidence_items(
    value: EvidenceItem | EvidenceCollection | Sequence[EvidenceItem],
) -> tuple[EvidenceItem, ...]:
    if isinstance(value, EvidenceItem):
        return (value,)
    if isinstance(value, EvidenceCollection):
        return value.items
    items = tuple(value)
    if not all(isinstance(item, EvidenceItem) for item in items):
        raise TypeError("evidence provider returned a non-evidence value")
    return items
