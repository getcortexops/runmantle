"""Restart-safe recovery coordination over the durable local store."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .approvals import ApprovalRequest, StoredApproval
from .capabilities import CapabilityRegistry
from .contracts import RiskLevel, TaskContract, TaskStatus
from .durable import DurableRuntime
from .evidence import (
    EvidenceCollection,
    EvidenceItem,
    EvidenceProviderRegistry,
    _as_agent_claim,
    new_id,
    utc_now,
)
from .persistence import (
    ConcurrentUpdateError,
    PersistenceStore,
    RecoveryStateRecord,
)
from .recovery import (
    RecoveryAction,
    RecoveryActionResult,
    RecoveryExecutionReceipt,
    RecoveryExecutorResult,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryPostcondition,
    RecoveryReason,
    RecoveryReasonCode,
    RecoveryResult,
    RecoveryStatus,
    RuntimeConfirmation,
    _callable_identity,
    _freeze_mapping,
    _stable_provider_configuration,
)
from .serialization import SafeJsonCodec, SerializationError
from .telemetry import EventSink, LifecycleEvent, LifecycleEventType, NullEventSink
from .verification import RuleBasedVerifier, Verifier

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]
DurableRecoveryHandler = Callable[
    [RecoveryAction, TaskContract[Any, Any]],
    Awaitable[RecoveryExecutorResult | Any],
]


@dataclass(frozen=True, slots=True)
class RecoveryHandlerRegistration:
    """Stable application-owned binding for one recovery handler."""

    handler: DurableRecoveryHandler
    handler_identity: str
    handler_configuration: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not callable(self.handler):
            raise TypeError("recovery handler registration requires a callable")
        if not self.handler_identity.strip():
            raise ValueError("recovery handler identity must not be empty")
        encoded = SafeJsonCodec().dumps(dict(self.handler_configuration))
        decoded = SafeJsonCodec().loads(encoded)
        if not isinstance(decoded, Mapping):
            raise TypeError("recovery handler configuration must be an object")
        object.__setattr__(
            self,
            "handler_configuration",
            _freeze_mapping(decoded),
        )


logger = logging.getLogger(__name__)

_TERMINAL_RECOVERY_STATES = {
    RecoveryStatus.BLOCKED.value,
    RecoveryStatus.FAILED.value,
    RecoveryStatus.POSTCONDITION_FAILED.value,
    RecoveryStatus.VERIFIED.value,
    RecoveryStatus.UNKNOWN.value,
    RecoveryStatus.DRY_RUN.value,
}

_RISK_ORDER: Mapping[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class DurableRecoveryExecutor:
    """Durable, exact-plan recovery executor with independent verification.

    A plan is re-supplied after restart because Python handlers, preconditions,
    and evidence providers are executable application code and are never
    deserialized from SQLite.
    """

    def __init__(
        self,
        *,
        store: PersistenceStore,
        registry: CapabilityRegistry,
        policy: RecoveryPolicy | None = None,
        handlers: Mapping[str, DurableRecoveryHandler | RecoveryHandlerRegistration]
        | None = None,
        evidence_providers: EvidenceProviderRegistry | None = None,
        verifier: Verifier | None = None,
        event_sink: EventSink | None = None,
        executor_id: str = "runmantle.durable_recovery",
        instance_id: str | None = None,
        clock: Clock = utc_now,
        id_factory: IdFactory = new_id,
    ) -> None:
        self.store = store
        self.registry = registry
        self.policy = policy or RecoveryPolicy.safe_default()
        self.handlers = {
            capability: (
                value
                if isinstance(value, RecoveryHandlerRegistration)
                else RecoveryHandlerRegistration(
                    handler=value,
                    handler_identity=_callable_identity(value),
                    handler_configuration={},
                )
            )
            for capability, value in (handlers or {}).items()
        }
        self.evidence_providers = evidence_providers or EvidenceProviderRegistry()
        self.evidence_providers.seal()
        self.verifier = verifier or RuleBasedVerifier(clock=clock)
        self.event_sink = event_sink or NullEventSink()
        self.executor_id = executor_id
        self.instance_id = instance_id or new_id()
        self.clock = clock
        self.id_factory = id_factory
        self.runtime = DurableRuntime(
            store=store,
            verifier=self.verifier,
            event_sink=self.event_sink,
            clock=clock,
            id_factory=id_factory,
        )

    async def execute(
        self,
        plan: RecoveryPlan,
        *,
        contract: TaskContract[Any, Any],
        preflight_confirmation: RuntimeConfirmation | None = None,
        dry_run: bool = False,
    ) -> RecoveryResult:
        """Start or resume exactly one recovery plan from durable boundaries."""

        self._validate_plan(plan, contract)
        self.store.validate_contract(plan.task_id, contract)
        action = plan.actions[0]
        state = self.store.load_recovery_state(plan.plan_id)
        if state is None:
            state = self.store.save_recovery_state(
                plan,
                status=RecoveryStatus.PLANNED.value,
                occurred_at=self.clock(),
            )
            self._append(
                plan,
                LifecycleEventType.RECOVERY_REQUESTED,
                details={
                    "plan_id": plan.plan_id,
                    "plan_hash": plan.plan_hash,
                    "action_id": action.action_id,
                    "action_hash": action.action_hash,
                    "failure_diagnosis": plan.failure_diagnosis,
                    "context_reference": plan.context_reference,
                    "declared_recovery_capability": (plan.declared_recovery_capability),
                    "risk_level": plan.risk_level,
                    "approval_required": plan.approval_required,
                    "preconditions": [item.name for item in plan.preconditions],
                    "postconditions": [
                        {
                            "name": item.name,
                            "evidence_type": item.evidence_type,
                            "required": item.required,
                            "provider_identity": item.provider_identity,
                            "provider_configuration": dict(item.provider_configuration),
                        }
                        for item in plan.postconditions
                    ],
                    "compensation_id": plan.compensation_id,
                    "proposed_by": plan.proposed_by,
                },
                dedupe_key=f"recovery:{plan.plan_id}:requested",
            )
        elif state.payload.get("plan_hash") != plan.plan_hash:
            raise ConcurrentUpdateError(
                "recovery plan ID has conflicting immutable content"
            )

        if state.status == RecoveryStatus.EXECUTING.value:
            if state.execution_owner_id != self.instance_id:
                state, event = self.store.mark_recovery_unknown(
                    plan,
                    expected_version=state.version,
                    occurred_at=self.clock(),
                    reason="a prior process stopped after recovery execution began",
                )
                self._publish(event)
            return self._result(plan, RecoveryStatus.UNKNOWN, state=state)
        if state.status == RecoveryStatus.UNKNOWN.value:
            return self._result(plan, RecoveryStatus.UNKNOWN, state=state)
        if state.status in _TERMINAL_RECOVERY_STATES:
            self._append(
                plan,
                LifecycleEventType.RECOVERY_DUPLICATE_PREVENTED,
                details={"plan_id": plan.plan_id, "persisted_status": state.status},
                dedupe_key=f"recovery:{plan.plan_id}:duplicate-prevented",
            )
            return self._result(
                plan,
                RecoveryStatus.DUPLICATE_PREVENTED,
                state=state,
                code=RecoveryReasonCode.DUPLICATE_IDEMPOTENCY_KEY,
                message="the durable recovery plan already reached a terminal state",
            )
        if state.status == RecoveryStatus.POSTCONDITIONS_SATISFIED.value:
            return self._verify_outcome(plan, contract, state)
        if state.status == RecoveryStatus.EXECUTOR_SUCCEEDED.value:
            return await self._complete_postconditions(plan, contract, state)

        blocked = self._policy_failure(plan, contract, action)
        if blocked is not None:
            return self._block(plan, state, *blocked)

        if preflight_confirmation is not None:
            confirmation_event = self.store.save_runtime_confirmation(
                plan.task_id,
                preflight_confirmation,
            )
            if confirmation_event is not None:
                self._publish(confirmation_event)
        confirmation = self._find_preflight(plan, action)
        declaration = self.registry.get(action.capability)
        assert declaration is not None
        preflight_required = (
            declaration.requires_pre_action_confirmation
            or self.policy.require_pre_action_confirmation
        )
        if preflight_required and confirmation is None:
            state = self._save_state(
                plan,
                state,
                RecoveryStatus.AWAITING_PREFLIGHT_CONFIRMATION,
            )
            self._append(
                plan,
                LifecycleEventType.RECOVERY_BLOCKED,
                details={
                    "plan_id": plan.plan_id,
                    "status": state.status,
                    "reason_code": (RecoveryReasonCode.PREFLIGHT_CONFIRMATION_REQUIRED),
                },
                dedupe_key=f"recovery:{plan.plan_id}:awaiting-preflight",
            )
            return self._result(
                plan,
                RecoveryStatus.AWAITING_PREFLIGHT_CONFIRMATION,
                state=state,
                code=RecoveryReasonCode.PREFLIGHT_CONFIRMATION_REQUIRED,
                message="exact pre-action capability confirmation is required",
            )
        if confirmation is not None and (
            not confirmation.supported or not confirmation.safe
        ):
            return self._block(
                plan,
                state,
                RecoveryReasonCode.PREFLIGHT_CONFIRMATION_REJECTED,
                "the exact pre-action capability confirmation rejected execution",
            )
        if confirmation is not None:
            self._append(
                plan,
                LifecycleEventType.RECOVERY_PREFLIGHT_CONFIRMED,
                details={
                    "plan_id": plan.plan_id,
                    "action_id": action.action_id,
                    "action_hash": action.action_hash,
                    "confirmation_id": confirmation.confirmation_id,
                },
                dedupe_key=f"recovery:{plan.plan_id}:preflight-confirmed",
            )

        for precondition in plan.preconditions:
            try:
                condition = precondition.evaluate(plan, action, contract)
            except Exception as error:  # noqa: BLE001 - fail closed
                return self._block(
                    plan,
                    state,
                    RecoveryReasonCode.PRECONDITION_FAILED,
                    f"precondition {precondition.name!r} raised: {error}",
                )
            if not condition.passed:
                return self._block(
                    plan,
                    state,
                    RecoveryReasonCode.PRECONDITION_FAILED,
                    condition.message,
                )

        approval_required = (
            plan.approval_required
            or declaration.requires_approval
            or action.capability in self.policy.approval_required_capabilities
        )
        approval: StoredApproval | None = None
        if approval_required:
            approval = self._find_approval(plan, action)
            if approval is None:
                self._ensure_approval_request(plan, action)
                state = self._save_state(
                    plan,
                    state,
                    RecoveryStatus.AWAITING_APPROVAL,
                )
                self._append(
                    plan,
                    LifecycleEventType.RECOVERY_AWAITING_APPROVAL,
                    details={
                        "plan_id": plan.plan_id,
                        "plan_hash": plan.plan_hash,
                        "approval_id": self._approval_id(plan),
                    },
                    dedupe_key=f"recovery:{plan.plan_id}:awaiting-approval",
                )
                return self._result(
                    plan,
                    RecoveryStatus.AWAITING_APPROVAL,
                    state=state,
                    code=RecoveryReasonCode.APPROVAL_REQUIRED,
                    message="an unexpired exact-plan approval is required",
                )

        if dry_run:
            state = self._save_state(plan, state, RecoveryStatus.DRY_RUN)
            return self._result(
                plan,
                RecoveryStatus.DRY_RUN,
                state=state,
                code=RecoveryReasonCode.DRY_RUN_COMPLETE,
                message="all pre-action gates passed; handler was not invoked",
            )

        handler_registration = self.handlers.get(action.capability)
        if handler_registration is None:
            return self._block(
                plan,
                state,
                RecoveryReasonCode.EXECUTOR_UNAVAILABLE,
                "no application recovery handler is registered",
            )
        state = self._save_state(plan, state, RecoveryStatus.AUTHORIZED)
        state, event = self.store.claim_recovery_execution(
            plan,
            expected_version=state.version,
            owner_id=self.instance_id,
            occurred_at=self.clock(),
            approval_id=(None if approval is None else approval.request.approval_id),
            approval_request_hash=(
                None if approval is None else approval.request.request_hash
            ),
            approval_scope=(None if approval is None else self._approval_scope(action)),
        )
        self._publish(event)
        started_at = self.clock()
        try:
            value = await handler_registration.handler(action, contract)
            if isinstance(value, RecoveryExecutorResult):
                executor_result = value
            else:
                executor_result = RecoveryExecutorResult(
                    succeeded=True,
                    output=value,
                )
            receipt = RecoveryExecutionReceipt(
                receipt_id=self.id_factory(),
                plan_id=plan.plan_id,
                action_id=action.action_id,
                action_hash=action.action_hash,
                executor_id=self.executor_id,
                status=(
                    RecoveryStatus.EXECUTOR_SUCCEEDED
                    if executor_result.succeeded
                    else RecoveryStatus.FAILED
                ),
                started_at=started_at,
                finished_at=self.clock(),
                output=executor_result.output,
                message=executor_result.message,
            )
        except Exception as error:  # noqa: BLE001 - effects may be partial
            receipt = RecoveryExecutionReceipt(
                receipt_id=self.id_factory(),
                plan_id=plan.plan_id,
                action_id=action.action_id,
                action_hash=action.action_hash,
                executor_id=self.executor_id,
                status=RecoveryStatus.UNKNOWN,
                started_at=started_at,
                finished_at=self.clock(),
                message=str(error),
                error_type=type(error).__name__,
            )
        try:
            state, event = self.store.finish_recovery_execution(
                plan,
                expected_version=state.version,
                owner_id=self.instance_id,
                receipt=receipt,
            )
        except SerializationError:
            state, event = self.store.mark_recovery_unknown(
                plan,
                expected_version=state.version,
                occurred_at=self.clock(),
                reason="recovery receipt could not be safely serialized",
            )
            self._publish(event)
            return self._result(
                plan,
                RecoveryStatus.UNKNOWN,
                state=state,
                code=RecoveryReasonCode.EXECUTION_INTERRUPTED,
                message="the recovery receipt could not be persisted safely",
            )
        self._publish(event)
        if receipt.status is not RecoveryStatus.EXECUTOR_SUCCEEDED:
            return self._result(plan, receipt.status, state=state, receipt=receipt)

        return await self._complete_postconditions(plan, contract, state)

    async def _complete_postconditions(
        self,
        plan: RecoveryPlan,
        contract: TaskContract[Any, Any],
        state: RecoveryStateRecord,
    ) -> RecoveryResult:
        action = plan.actions[0]
        receipt = self._receipt_from_state(state)
        if receipt is None or receipt.status is not RecoveryStatus.EXECUTOR_SUCCEEDED:
            raise ValueError("persisted successful recovery has no valid receipt")
        evidence, required_failures = await self._acquire_postconditions(
            plan,
            action,
            receipt,
        )
        refreshed_state = self.store.load_recovery_state(plan.plan_id)
        assert refreshed_state is not None
        state = refreshed_state
        if required_failures:
            state = self._save_state(
                plan,
                state,
                RecoveryStatus.POSTCONDITION_FAILED,
            )
            self._append(
                plan,
                LifecycleEventType.RECOVERY_POSTCONDITION_FAILED,
                details={
                    "plan_id": plan.plan_id,
                    "failures": list(required_failures),
                    "executor_succeeded": True,
                    "outcome_verified": False,
                },
                dedupe_key=f"recovery:{plan.plan_id}:postcondition-failed",
            )
            return self._result(
                plan,
                RecoveryStatus.POSTCONDITION_FAILED,
                state=state,
                receipt=receipt,
                evidence=evidence,
                code=RecoveryReasonCode.POSTCONDITION_FAILED,
                message="required external postcondition evidence was not acquired",
            )
        state = self._save_state(
            plan,
            state,
            RecoveryStatus.POSTCONDITIONS_SATISFIED,
        )
        return self._verify_outcome(plan, contract, state, receipt=receipt)

    def _validate_plan(
        self,
        plan: RecoveryPlan,
        contract: TaskContract[Any, Any],
    ) -> None:
        if plan.task_id != contract.task_id:
            raise ValueError("recovery plan task does not match contract")
        if len(plan.actions) != 1:
            raise ValueError("durable recovery requires exactly one action per plan")
        if not plan.preconditions:
            raise ValueError("durable recovery requires an explicit precondition")
        if not plan.postconditions:
            raise ValueError("durable recovery requires an explicit postcondition")
        action = plan.actions[0]
        registration = self.handlers.get(action.capability)
        if registration is not None:
            if action.handler_identity != registration.handler_identity:
                raise ValueError(
                    "recovery handler identity differs from the approved plan"
                )
            if SafeJsonCodec().dumps(
                action.handler_configuration
            ) != SafeJsonCodec().dumps(registration.handler_configuration):
                raise ValueError(
                    "recovery handler configuration differs from the approved plan"
                )
        for postcondition in plan.postconditions:
            assert postcondition.provider_identity is not None
            provider_registration = self.evidence_providers.registration_for(
                postcondition.provider,
                provider_identity=postcondition.provider_identity,
                provider_configuration=postcondition.provider_configuration,
            )
            if provider_registration is not None:
                continue
            if postcondition.provider_identity != _callable_identity(
                postcondition.provider.acquire
            ):
                raise ValueError(
                    "recovery evidence provider identity differs from the plan"
                )
            if SafeJsonCodec().dumps(
                postcondition.provider_configuration
            ) != SafeJsonCodec().dumps(
                _stable_provider_configuration(postcondition.provider)
            ):
                raise ValueError(
                    "recovery evidence provider configuration differs from the plan"
                )

    def _policy_failure(
        self,
        plan: RecoveryPlan,
        contract: TaskContract[Any, Any],
        action: RecoveryAction,
    ) -> tuple[RecoveryReasonCode, str] | None:
        task = self.store.load_task(plan.task_id)
        declaration = self.registry.get(action.capability)
        if declaration is None:
            return (
                RecoveryReasonCode.UNSUPPORTED_CAPABILITY,
                "recovery capability is not registered",
            )
        if not declaration.available or not declaration.recovery_supported:
            return (
                RecoveryReasonCode.CAPABILITY_UNAVAILABLE,
                "recovery capability is unavailable or not recovery-enabled",
            )
        if (
            action.capability not in self.policy.allowed_capabilities
            or action.capability not in contract.allowed_capabilities
        ):
            return (
                RecoveryReasonCode.POLICY_DENIED,
                "recovery capability is not allowed",
            )
        if (
            task.status not in self.policy.allowed_task_states
            or task.status not in declaration.supported_task_states
        ):
            return (
                RecoveryReasonCode.INVALID_TASK_STATE,
                f"recovery is not allowed while task is {task.status.value}",
            )
        if _RISK_ORDER[plan.risk_level] > _RISK_ORDER[self.policy.maximum_risk_level]:
            return (
                RecoveryReasonCode.RISK_EXCEEDS_CAPABILITY,
                "plan risk exceeds policy",
            )
        if _RISK_ORDER[plan.risk_level] > _RISK_ORDER[declaration.maximum_risk_level]:
            return (
                RecoveryReasonCode.RISK_EXCEEDS_CAPABILITY,
                "plan risk exceeds capability maximum",
            )
        if (
            declaration.requires_idempotency
            and action.idempotency_key != contract.idempotency_key
        ):
            return (
                RecoveryReasonCode.IDEMPOTENCY_MISMATCH,
                "recovery idempotency key does not match the task contract",
            )
        return None

    def _find_preflight(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
    ) -> RuntimeConfirmation | None:
        for item in reversed(self.store.runtime_confirmations(plan.task_id)):
            if (
                item.action_id == action.action_id
                and item.capability == action.capability
                and item.idempotency_key == action.idempotency_key
                and item.target_hash == action.action_hash
            ):
                return item
        return None

    async def _acquire_postconditions(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: RecoveryExecutionReceipt,
    ) -> tuple[EvidenceCollection, tuple[str, ...]]:
        failures: list[str] = []
        for postcondition in plan.postconditions:
            try:
                acquired = await postcondition.provider.acquire(plan, action, receipt)
                items = tuple(
                    self._establish_provider_evidence(postcondition, item)
                    for item in _evidence_items(acquired)
                )
                if postcondition.evidence_type is not None and any(
                    item.type != postcondition.evidence_type for item in items
                ):
                    raise ValueError("provider returned the wrong evidence type")
                if postcondition.required and not items:
                    raise ValueError("provider returned no evidence")
                for item in items:
                    _, events = self.store.record_recovery_evidence(
                        plan.plan_id,
                        postcondition_name=postcondition.name,
                        item=item,
                        occurred_at=self.clock(),
                    )
                    for event in events:
                        self._publish(event)
            except Exception as error:  # noqa: BLE001 - evidence gate fails closed
                if postcondition.required:
                    failures.append(
                        f"{postcondition.name}: {type(error).__name__}: {error}"
                    )
        return self.store.recovery_evidence(plan.plan_id), tuple(failures)

    def _establish_provider_evidence(
        self,
        postcondition: RecoveryPostcondition,
        item: EvidenceItem,
    ) -> EvidenceItem:
        assert postcondition.provider_identity is not None
        established = self.evidence_providers._establish(
            postcondition.provider,
            item,
            boundary="durable_recovery_postcondition",
            provider_identity=postcondition.provider_identity,
            provider_configuration=postcondition.provider_configuration,
        )
        return established if established is not None else _as_agent_claim(item)

    def _verify_outcome(
        self,
        plan: RecoveryPlan,
        contract: TaskContract[Any, Any],
        state: RecoveryStateRecord,
        *,
        receipt: RecoveryExecutionReceipt | None = None,
    ) -> RecoveryResult:
        result = self.runtime.verify_after_recovery(
            plan.task_id,
            plan_id=plan.plan_id,
            contract=contract,
            verifier=self.verifier,
        )
        final_status = (
            RecoveryStatus.VERIFIED
            if result.status is TaskStatus.VERIFIED
            else RecoveryStatus.FAILED
        )
        state = self._save_state(plan, state, final_status)
        event_type = (
            LifecycleEventType.RECOVERY_OUTCOME_VERIFIED
            if final_status is RecoveryStatus.VERIFIED
            else LifecycleEventType.RECOVERY_BLOCKED
        )
        self._append(
            plan,
            event_type,
            details={
                "plan_id": plan.plan_id,
                "recovery_status": final_status,
                "task_status": result.status,
                "only_verified_is_success": True,
            },
            dedupe_key=f"recovery:{plan.plan_id}:outcome-verification",
        )
        return self._result(
            plan,
            final_status,
            state=state,
            receipt=receipt or self._receipt_from_state(state),
            evidence=self.store.recovery_evidence(plan.plan_id),
            code=(
                RecoveryReasonCode.EXECUTED
                if final_status is RecoveryStatus.VERIFIED
                else RecoveryReasonCode.OUTCOME_NOT_VERIFIED
            ),
            message=(
                "recovery postconditions and task outcome were verified"
                if final_status is RecoveryStatus.VERIFIED
                else "recovery executed but final task outcome did not verify"
            ),
        )

    def _ensure_approval_request(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
    ) -> None:
        request = ApprovalRequest(
            approval_id=self._approval_id(plan),
            task_id=plan.task_id,
            target_id=plan.plan_id,
            target_hash=self._approval_target_hash(plan),
            required_scope=self._approval_scope(action),
            risk_level=plan.risk_level,
            reason=(
                f"Authorize recovery plan {plan.plan_id!r} with exact hash "
                f"{plan.plan_hash}."
            ),
            created_at=plan.created_at,
            expires_at=plan.created_at + timedelta(days=1),
            one_time_use=True,
            metadata={
                "plan_hash": plan.plan_hash,
                "action_hash": action.action_hash,
                "capability": action.capability,
                "failure_diagnosis": plan.failure_diagnosis,
            },
        )
        _, event = self.store.create_approval_request(request)
        if event is not None:
            self._publish(event)

    def _find_approval(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
    ) -> StoredApproval | None:
        return self.store.find_approval(
            plan.task_id,
            target_hash=self._approval_target_hash(plan),
            required_scope=self._approval_scope(action),
            occurred_at=self.clock(),
        )

    def _block(
        self,
        plan: RecoveryPlan,
        state: RecoveryStateRecord,
        code: RecoveryReasonCode,
        message: str,
    ) -> RecoveryResult:
        state = self._save_state(plan, state, RecoveryStatus.BLOCKED)
        self._append(
            plan,
            LifecycleEventType.RECOVERY_BLOCKED,
            details={
                "plan_id": plan.plan_id,
                "status": RecoveryStatus.BLOCKED,
                "reason_code": code,
                "reason": message,
            },
            dedupe_key=f"recovery:{plan.plan_id}:blocked:{code.value}",
        )
        return self._result(
            plan,
            RecoveryStatus.BLOCKED,
            state=state,
            code=code,
            message=message,
        )

    def _save_state(
        self,
        plan: RecoveryPlan,
        state: RecoveryStateRecord,
        status: RecoveryStatus,
    ) -> RecoveryStateRecord:
        if state.status == status.value:
            return state
        return self.store.save_recovery_state(
            plan,
            status=status.value,
            occurred_at=self.clock(),
            expected_version=state.version,
        )

    def _result(
        self,
        plan: RecoveryPlan,
        status: RecoveryStatus,
        *,
        state: RecoveryStateRecord,
        receipt: RecoveryExecutionReceipt | None = None,
        evidence: EvidenceCollection | None = None,
        code: RecoveryReasonCode = RecoveryReasonCode.EXECUTION_INTERRUPTED,
        message: str = "recovery did not reach verified outcome",
    ) -> RecoveryResult:
        del state
        action = plan.actions[0]
        return RecoveryResult(
            plan_id=plan.plan_id,
            task_id=plan.task_id,
            status=status,
            actions=(
                RecoveryActionResult(
                    action_id=action.action_id,
                    capability=action.capability,
                    status=status,
                    reason=RecoveryReason(code=code, message=message),
                    executor_receipt=receipt,
                    postcondition_evidence=(
                        evidence or self.store.recovery_evidence(plan.plan_id)
                    ),
                    error_type=None if receipt is None else receipt.error_type,
                ),
            ),
        )

    def _receipt_from_state(
        self,
        state: RecoveryStateRecord,
    ) -> RecoveryExecutionReceipt | None:
        value = state.receipt
        if value is None:
            refreshed = self.store.load_recovery_state(state.plan_id)
            value = None if refreshed is None else refreshed.receipt
        if value is None:
            return None
        receipt = RecoveryExecutionReceipt(
            receipt_id=str(value["receipt_id"]),
            plan_id=str(value["plan_id"]),
            action_id=str(value["action_id"]),
            action_hash=str(value["action_hash"]),
            executor_id=str(value["executor_id"]),
            status=RecoveryStatus(str(value["status"])),
            started_at=datetime.fromisoformat(str(value["started_at"])),
            finished_at=datetime.fromisoformat(str(value["finished_at"])),
            output=value.get("output"),
            message=str(value.get("message", "")),
            error_type=(
                None if value.get("error_type") is None else str(value["error_type"])
            ),
        )
        if value.get("output_hash") != receipt.output_hash:
            raise ValueError("persisted recovery receipt output hash does not match")
        return receipt

    def _append(
        self,
        plan: RecoveryPlan,
        event_type: LifecycleEventType,
        *,
        details: Mapping[str, Any],
        dedupe_key: str,
    ) -> None:
        event, inserted = self.store.append_event_once(
            plan.task_id,
            event_type=event_type,
            occurred_at=self.clock(),
            name=event_type.value,
            details=details,
            dedupe_key=dedupe_key,
        )
        if inserted:
            self._publish(event)

    def _publish(self, event: LifecycleEvent) -> None:
        try:
            self.event_sink.emit(event)
        except Exception:
            logger.warning(
                "external recovery event sink failed after durable commit",
                exc_info=True,
            )

    @staticmethod
    def _approval_id(plan: RecoveryPlan) -> str:
        return f"recovery:{plan.plan_id}:approval"

    @staticmethod
    def _approval_target_hash(plan: RecoveryPlan) -> str:
        return f"recovery:{plan.plan_hash}"

    @staticmethod
    def _approval_scope(action: RecoveryAction) -> str:
        return f"recovery:{action.capability}:execute"


def _evidence_items(
    value: EvidenceItem | EvidenceCollection | Sequence[EvidenceItem],
) -> tuple[EvidenceItem, ...]:
    if isinstance(value, EvidenceItem):
        return (value,)
    if isinstance(value, EvidenceCollection):
        return tuple(value)
    return tuple(value)
