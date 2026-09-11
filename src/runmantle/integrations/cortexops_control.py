"""Optional fail-closed control client for a CortexOps v1 control plane."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from runmantle.actions import (
    ActionExecutionResult,
    ActionExecutionStatus,
    ActionPolicy,
    ActionRequest,
    MediatedActionExecutor,
    PostActionRuntimeConfirmation,
    PostActionRuntimeConfirmationProvider,
    PostActionRuntimeConfirmationStatus,
)
from runmantle.approvals import ApprovalDecision, ApproverIdentity
from runmantle.contracts import RiskLevel, TaskContract, TaskStatus
from runmantle.core import CancellationToken, TaskResult
from runmantle.durable_recovery import DurableRecoveryExecutor
from runmantle.evidence import EvidenceCollection, new_id
from runmantle.persistence import TaskNotFoundError
from runmantle.recovery import (
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryResult,
    RecoveryStatus,
    RuntimeConfirmation,
)
from runmantle.serialization import SafeJsonCodec
from runmantle.telemetry import task_contract_telemetry

PROTOCOL_VERSION = 1
_ACTION_OUTCOMES = frozenset({"ALLOW", "BLOCK", "REQUIRE_APPROVAL"})


class CortexOpsControlError(RuntimeError):
    """Base error for authoritative control requests."""


class CortexOpsControlUnavailable(CortexOpsControlError):
    """No authoritative response was received; callers must fail closed."""


class CortexOpsControlRejected(CortexOpsControlError):
    """The control plane rejected an invalid, stale, or unauthorized request."""


class CortexOpsControlTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...


AuthorizationProvider = Callable[[], str | None]


@dataclass(slots=True)
class UrllibCortexOpsControlTransport:
    """Small HTTP transport using application-supplied authorization."""

    base_url: str
    authorization_provider: AuthorizationProvider | None = None
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if not self.base_url:
            raise ValueError("CortexOps control base_url must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("CortexOps control timeout must be positive")

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = SafeJsonCodec().dumps(dict(payload)).encode("utf-8")
            headers["Content-Type"] = "application/json"
        authorization = (
            None
            if self.authorization_provider is None
            else self.authorization_provider()
        )
        if authorization:
            headers["Authorization"] = authorization
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method.upper(),
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                value = json.loads(response.read())
        except HTTPError as error:
            detail = _http_error_detail(error)
            raise CortexOpsControlRejected(
                f"CortexOps control rejected request ({error.code}): {detail}"
            ) from error
        except (OSError, URLError, TimeoutError) as error:
            raise CortexOpsControlUnavailable(
                "CortexOps control plane is unavailable"
            ) from error
        except (json.JSONDecodeError, TypeError) as error:
            raise CortexOpsControlUnavailable(
                "CortexOps control response was not valid JSON"
            ) from error
        if not isinstance(value, Mapping):
            raise CortexOpsControlUnavailable(
                "CortexOps control response was not an object"
            )
        return value


@dataclass(slots=True)
class CortexOpsControlClient:
    """Versioned standalone client; construction grants no authority."""

    transport: CortexOpsControlTransport
    runtime_id: str
    runtime_version: str
    mode: str = "control"
    data_mode: str = "live"
    _handshake: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def register_runtime(
        self,
        capabilities: frozenset[str] | set[str] | tuple[str, ...],
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "request_id": request_id or f"runtime:{self.runtime_id}:register",
            "protocol_version": PROTOCOL_VERSION,
            "runtime_id": self.runtime_id,
            "runtime_version": self.runtime_version,
            "mode": self.mode,
            "data_mode": self.data_mode,
            "capabilities": sorted(capabilities),
        }
        response = self._request("POST", "/runtimes/register", payload)
        if response.get("runtime_id") != self.runtime_id:
            raise CortexOpsControlRejected("runtime handshake identity mismatch")
        self._handshake = response
        return response

    @property
    def handshake(self) -> Mapping[str, Any]:
        if self._handshake is None:
            raise CortexOpsControlRejected("runtime handshake is required")
        return self._handshake

    def register_task(
        self,
        contract: TaskContract[Any, Any],
        *,
        correlation_id: str,
        worker_id: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        contract_hash = _digest(task_contract_telemetry(contract))
        return self._request(
            "POST",
            "/tasks/register",
            {
                "request_id": request_id
                or f"runtime:{self.runtime_id}:task:{contract.task_id}:register",
                "runtime_id": self.runtime_id,
                "task_id": contract.task_id,
                "contract_hash": contract_hash,
                "correlation_id": correlation_id,
                "worker_id": worker_id,
            },
        )

    def sync_task_result(
        self,
        contract: TaskContract[Any, Any],
        result: TaskResult[Any],
        *,
        sequence: int,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": request_id
            or (f"runtime:{self.runtime_id}:task:{contract.task_id}:status:{sequence}"),
            "runtime_id": self.runtime_id,
            "task_id": contract.task_id,
            "contract_hash": _digest(task_contract_telemetry(contract)),
            "status": result.status.value,
            "sequence": sequence,
        }
        if result.status is TaskStatus.VERIFIED:
            verification = result.final_verification_result
            if verification is None:
                raise ValueError("verified task result requires verification details")
            payload["verification_hash"] = _digest(
                {
                    "status": verification.status.value,
                    "criteria": [
                        {
                            "name": item.name,
                            "passed": item.passed,
                            "conclusive": item.conclusive,
                        }
                        for item in verification.criteria
                    ],
                    "evidence_ids": [item.evidence_id for item in result.evidence],
                }
            )
        return self._request("POST", "/tasks/status", payload)

    def evaluate_action(
        self,
        request: ActionRequest,
        *,
        correlation_id: str,
        worker_id: str,
    ) -> dict[str, Any]:
        policy = self.handshake.get("policy")
        if not isinstance(policy, Mapping):
            raise CortexOpsControlRejected("handshake omitted active policy")
        facts = _policy_facts(
            policy,
            request,
            worker_id=worker_id,
        )
        response = self._request(
            "POST",
            "/actions/evaluate",
            {
                "request_id": (
                    f"runtime:{self.runtime_id}:action:{request.action_id}:"
                    f"{request.action_hash}"
                ),
                "runtime_id": self.runtime_id,
                "task_id": request.task_id,
                "correlation_id": correlation_id,
                "worker_id": worker_id,
                "action_id": request.action_id,
                "action_hash": request.action_hash,
                "input_hash": request.input_hash,
                "action_name": request.name,
                "required_capability": request.required_capability,
                "risk_level": request.risk_level.value,
                "policy_version": policy["version"],
                "policy_hash": policy["hash"],
                "facts": {"rule_evaluations": facts},
                "adapter_version": PROTOCOL_VERSION,
            },
        )
        return _validated_action_decision(
            response,
            expected_action_hash=request.action_hash,
        )

    def action_decision(self, decision_id: str, action_hash: str) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"/actions/{self.runtime_id}/{decision_id}",
        )
        return _validated_action_decision(
            response,
            expected_action_hash=action_hash,
        )

    def dispatch_action(
        self,
        decision: Mapping[str, Any],
        *,
        action_hash: str,
        attempt_id: str,
    ) -> dict[str, Any]:
        validated = _validated_action_decision(
            decision,
            expected_action_hash=action_hash,
        )
        if validated["outcome"] not in {"ALLOW", "REQUIRE_APPROVAL"}:
            raise CortexOpsControlRejected("action decision does not permit dispatch")
        approval = validated.get("approval")
        if approval is not None and not isinstance(approval, Mapping):
            raise CortexOpsControlRejected("approval response is malformed")
        response = self._request(
            "POST",
            f"/actions/{validated['decision_id']}/dispatch",
            {
                "runtime_id": self.runtime_id,
                "action_hash": action_hash,
                "attempt_id": attempt_id,
                "permit_id": None if approval is None else approval.get("permit_id"),
                "permit_hash": None
                if approval is None
                else approval.get("permit_hash"),
            },
        )
        if (
            response.get("decision_id") != validated["decision_id"]
            or response.get("attempt_id") != attempt_id
            or response.get("state") != "DISPATCHED"
            or not isinstance(response.get("permit_consumed"), bool)
        ):
            raise CortexOpsControlRejected("dispatch response is malformed or denied")
        if approval is not None and response["permit_consumed"] is not True:
            raise CortexOpsControlRejected(
                "approved dispatch did not consume its permit"
            )
        return response

    def send_action_receipt(
        self,
        decision: Mapping[str, Any],
        result: ActionExecutionResult,
        *,
        attempt_id: str,
    ) -> dict[str, Any]:
        receipt = result.action.receipt
        if receipt is None:
            raise ValueError("action result has no executor receipt")
        outcome = {
            ActionExecutionStatus.EXECUTOR_SUCCEEDED: "succeeded",
            ActionExecutionStatus.FAILED: "failed",
            ActionExecutionStatus.CANCELLED: "failed",
            ActionExecutionStatus.UNKNOWN: "unknown",
        }.get(receipt.status)
        if outcome is None:
            raise ValueError("action result has no live execution receipt")
        return self._request(
            "POST",
            f"/actions/{decision['decision_id']}/receipts",
            {
                "runtime_id": self.runtime_id,
                "action_hash": receipt.action_hash,
                "receipt_id": f"{self.runtime_id}:{receipt.receipt_id}",
                "attempt_id": attempt_id,
                "runtime_execution_id": receipt.action_id,
                "outcome": outcome,
                "occurred_at": receipt.finished_at.isoformat(),
                "started_at": receipt.started_at.isoformat(),
                "ended_at": receipt.finished_at.isoformat(),
                "side_effect_confirmation": False,
            },
        )

    def send_post_action_confirmation(
        self,
        decision: Mapping[str, Any],
        confirmation: PostActionRuntimeConfirmation,
    ) -> dict[str, Any]:
        """Submit independent target observation; this is not a receipt claim."""

        receipt_id = f"{self.runtime_id}:{confirmation.receipt_id}"
        # CortexOps binds an independent observation to the already-audited
        # execution receipt.  Preserve the provider's evidence alongside that
        # receipt reference; neither is outcome verification evidence.
        evidence_ids = [
            receipt_id,
            *(
                item.evidence_id
                for item in confirmation.evidence
                if item.evidence_id != receipt_id
            ),
        ]
        return self._request(
            "POST",
            f"/actions/{decision['decision_id']}/runtime-confirmations",
            {
                "message_id": (
                    f"runtime:{self.runtime_id}:confirmation:"
                    f"{confirmation.confirmation_id}"
                ),
                "runtime_id": self.runtime_id,
                "task_id": confirmation.task_id,
                "action_id": confirmation.action_id,
                "action_hash": confirmation.action_hash,
                "receipt_id": receipt_id,
                "confirmation_id": confirmation.confirmation_id,
                "status": confirmation.status.value,
                "provider_id": confirmation.provider_id,
                "observed_state": dict(confirmation.observed_state),
                "expected_state": dict(confirmation.expected_state),
                "evidence_ids": evidence_ids,
                "checked_at": confirmation.checked_at.isoformat(),
                "actor": confirmation.actor,
            },
        )

    def submit_recovery(
        self,
        plan: RecoveryPlan,
        *,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        if len(plan.actions) != 1:
            raise ValueError(
                "CortexOps-controlled recovery requires exactly one action per plan"
            )
        action = plan.actions[0]
        return self._request(
            "POST",
            "/recovery/reviews",
            {
                "request_id": (
                    f"runtime:{self.runtime_id}:recovery:{plan.plan_id}:"
                    f"{plan.plan_hash}"
                ),
                "runtime_id": self.runtime_id,
                "task_id": plan.task_id,
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "action_id": action.action_id,
                "action_hash": action.action_hash,
                "capability": action.capability,
                "risk_level": plan.risk_level.value,
                "created_at": plan.created_at.isoformat(),
                "expires_at": (
                    expires_at or plan.created_at + timedelta(hours=1)
                ).isoformat(),
            },
        )

    def recovery_instruction(self, review_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/recovery/reviews/{review_id}?runtime_id={self.runtime_id}",
        )

    def send_recovery_result(
        self,
        review: Mapping[str, Any],
        result: RecoveryResult,
    ) -> dict[str, Any]:
        if not result.actions:
            raise ValueError("recovery result has no action result")
        action_result = result.actions[0]
        receipt = action_result.executor_receipt
        if receipt is None:
            raise ValueError("recovery result has no executor receipt")
        self._request(
            "POST",
            f"/recovery/reviews/{review['review_id']}/receipts",
            {
                "message_id": (
                    f"runtime:{self.runtime_id}:recovery-receipt:{receipt.receipt_id}"
                ),
                "runtime_id": self.runtime_id,
                "instruction_id": review["instruction_id"],
                "plan_hash": review["plan_hash"],
                "action_hash": review["action_hash"],
                "receipt_id": f"{self.runtime_id}:{receipt.receipt_id}",
                "status": receipt.status.value,
                "occurred_at": receipt.finished_at.isoformat(),
            },
        )
        verification_status = (
            "verified"
            if result.status is RecoveryStatus.VERIFIED
            else "failed"
            if result.status
            in {RecoveryStatus.FAILED, RecoveryStatus.POSTCONDITION_FAILED}
            else "inconclusive"
        )
        verification = {
            "status": verification_status,
            "evidence_ids": [
                item.evidence_id for item in action_result.postcondition_evidence
            ],
        }
        return self._request(
            "POST",
            f"/recovery/reviews/{review['review_id']}/verification",
            {
                "message_id": (
                    f"runtime:{self.runtime_id}:recovery-verification:"
                    f"{review['review_id']}"
                ),
                "runtime_id": self.runtime_id,
                "instruction_id": review["instruction_id"],
                "plan_hash": review["plan_hash"],
                "action_hash": review["action_hash"],
                "status": verification_status,
                "verification_hash": _digest(verification),
                "evidence_ids": verification["evidence_ids"],
            },
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = self.transport.request(
                method,
                f"/api/runmantle/v1{path}",
                payload,
            )
        except CortexOpsControlError:
            raise
        except Exception as error:
            raise CortexOpsControlUnavailable(
                "CortexOps control plane is unavailable"
            ) from error
        if not isinstance(response, Mapping):
            raise CortexOpsControlRejected(
                "CortexOps control response was not an object"
            )
        try:
            return dict(response)
        except (TypeError, ValueError) as error:
            raise CortexOpsControlRejected(
                "CortexOps control response could not be parsed"
            ) from error


@dataclass(slots=True)
class CortexOpsControlledActionExecutor:
    """Route one local mediated action through authoritative CortexOps gates."""

    local: MediatedActionExecutor
    control: CortexOpsControlClient
    correlation_id: str
    worker_id: str
    post_action_confirmation_provider: PostActionRuntimeConfirmationProvider | None = (
        None
    )

    async def execute(
        self,
        request: ActionRequest,
        *,
        contract: TaskContract[Any, Any],
        handler: Any,
        granted_capabilities: frozenset[str] | None = None,
        cancellation: CancellationToken | None = None,
        dry_run: bool = False,
    ) -> ActionExecutionResult:
        try:
            decision = self.control.evaluate_action(
                request,
                correlation_id=self.correlation_id,
                worker_id=self.worker_id,
            )
        except CortexOpsControlError:
            return await self._blocked(
                request,
                contract=contract,
                handler=handler,
                granted_capabilities=granted_capabilities,
                cancellation=cancellation,
                dry_run=dry_run,
            )
        outcome = decision["outcome"]
        requires_approval = outcome == "REQUIRE_APPROVAL"
        executor = self._local_executor(request, requires_approval=requires_approval)
        if outcome == "BLOCK":
            return await self._blocked(
                request,
                contract=contract,
                handler=handler,
                granted_capabilities=granted_capabilities,
                cancellation=cancellation,
                dry_run=dry_run,
            )
        if requires_approval:
            initial = await executor.execute(
                request,
                contract=contract,
                handler=handler,
                granted_capabilities=granted_capabilities,
                cancellation=cancellation,
                dry_run=dry_run,
            )
            decision = self.control.action_decision(
                str(decision["decision_id"]), request.action_hash
            )
            approval = decision.get("approval")
            if not isinstance(approval, Mapping):
                return initial
            approval_status = str(approval.get("status") or "")
            if approval_status in {"denied", "rejected", "cancelled"}:
                self._record_local_approval(request, approval, approved=False)
                return await executor.execute(
                    request,
                    contract=contract,
                    handler=handler,
                    granted_capabilities=granted_capabilities,
                    cancellation=cancellation,
                    dry_run=dry_run,
                )
            if approval_status != "approved":
                return initial
        else:
            initial = None
            approval = None
        try:
            existing = self.local.store.load_action(request.action_id)
        except TaskNotFoundError:
            existing = None
        attempt_id = f"rmattempt_{request.action_hash[:24]}"
        if existing is None or existing.receipt is None:
            try:
                self.control.dispatch_action(
                    decision,
                    action_hash=request.action_hash,
                    attempt_id=attempt_id,
                )
            except CortexOpsControlError:
                if (
                    existing is None
                    or existing.status is ActionExecutionStatus.REQUESTED
                ):
                    return await self._blocked(
                        request,
                        contract=contract,
                        handler=handler,
                        granted_capabilities=granted_capabilities,
                        cancellation=cancellation,
                        dry_run=dry_run,
                    )
                return initial or ActionExecutionResult(action=existing)
        if approval is not None:
            self._record_local_approval(request, approval, approved=True)
        result = await executor.execute(
            request,
            contract=contract,
            handler=handler,
            granted_capabilities=granted_capabilities,
            cancellation=cancellation,
            dry_run=dry_run,
        )
        receipt = result.action.receipt
        if receipt is not None and not dry_run:
            # Receipt delivery failure must never repeat a side effect.  The
            # receipt is already durable in the mediated action store; callers
            # may safely invoke this executor again to replay delivery.
            try:
                self.control.send_action_receipt(
                    decision,
                    result,
                    attempt_id=attempt_id,
                )
            except CortexOpsControlError:
                return result
            if (
                receipt.status is ActionExecutionStatus.EXECUTOR_SUCCEEDED
                and self.post_action_confirmation_provider is not None
            ):
                try:
                    confirmation = await self.post_action_confirmation_provider.confirm(
                        request, receipt
                    )
                    if (
                        confirmation.task_id != request.task_id
                        or confirmation.action_id != request.action_id
                        or confirmation.action_hash != request.action_hash
                        or confirmation.receipt_id != receipt.receipt_id
                    ):
                        raise CortexOpsControlRejected(
                            "post-action confirmation is not bound to this action "
                            "receipt"
                        )
                    self.control.send_post_action_confirmation(decision, confirmation)
                    result = ActionExecutionResult(
                        action=result.action,
                        outcome_evidence=result.outcome_evidence,
                        postcondition_errors=result.postcondition_errors,
                        duplicate_prevented=result.duplicate_prevented,
                        post_action_confirmation=confirmation,
                    )
                except CortexOpsControlError:
                    # Independent observation may be replayed separately; it
                    # cannot turn a completed action into another execution.
                    pass
                except Exception as error:  # noqa: BLE001 - probe failures are evidence
                    confirmation = PostActionRuntimeConfirmation(
                        confirmation_id=new_id(),
                        task_id=request.task_id,
                        action_id=request.action_id,
                        action_hash=request.action_hash,
                        receipt_id=receipt.receipt_id,
                        status=PostActionRuntimeConfirmationStatus.INCONCLUSIVE,
                        provider_id=type(
                            self.post_action_confirmation_provider
                        ).__name__,
                        observed_state={"probe_error": type(error).__name__},
                        expected_state={},
                        evidence=EvidenceCollection(),
                        checked_at=datetime.now(UTC),
                        actor="runmantle.controlled_action_executor",
                    )
                    try:
                        self.control.send_post_action_confirmation(
                            decision, confirmation
                        )
                        result = ActionExecutionResult(
                            action=result.action,
                            outcome_evidence=result.outcome_evidence,
                            postcondition_errors=result.postcondition_errors,
                            duplicate_prevented=result.duplicate_prevented,
                            post_action_confirmation=confirmation,
                        )
                    except CortexOpsControlError:
                        pass
        return result

    async def _blocked(
        self, request: ActionRequest, **kwargs: Any
    ) -> ActionExecutionResult:
        executor = self._local_executor(request, allowed=False)
        return await executor.execute(request, **kwargs)

    def _local_executor(
        self,
        request: ActionRequest,
        *,
        allowed: bool = True,
        requires_approval: bool = False,
    ) -> MediatedActionExecutor:
        return MediatedActionExecutor(
            store=self.local.store,
            capabilities=self.local.capabilities,
            policy=ActionPolicy(
                allowed_capabilities=(
                    frozenset({request.required_capability}) if allowed else frozenset()
                ),
                allowed_task_states=frozenset(TaskStatus),
                maximum_risk_level=RiskLevel.CRITICAL,
                approval_required_capabilities=(
                    frozenset({request.required_capability})
                    if requires_approval
                    else frozenset()
                ),
            ),
            evidence_providers=self.local.evidence_providers,
            event_sink=self.local.event_sink,
            executor_id=self.local.executor_id,
            instance_id=self.local.instance_id,
            clock=self.local.clock,
            id_factory=self.local.id_factory,
        )

    def _record_local_approval(
        self,
        request: ActionRequest,
        approval: Mapping[str, Any],
        *,
        approved: bool,
    ) -> None:
        stored = self.local.store.load_approval(request.approval_id)
        if (
            stored.request.task_id != request.task_id
            or stored.request.target_hash != request.approval_key
            or stored.request.required_scope != request.approval_scope
        ):
            raise CortexOpsControlRejected(
                "local approval request is not bound to the governed action"
            )
        if stored.decision is not None:
            return
        decided_at = _aware_datetime(approval.get("decided_at") or datetime.now(UTC))
        recorder = getattr(self.local.store, "record_approval_decision", None)
        if not callable(recorder):
            raise TypeError("action store cannot persist approval decisions")
        recorder(
            ApprovalDecision(
                decision_id=f"cortexops:{approval['approval_id']}",
                approval_id=stored.request.approval_id,
                request_hash=stored.request.request_hash,
                approved=approved,
                approver=ApproverIdentity(
                    subject=str(approval.get("approver_id") or "cortexops-operator"),
                    issuer="cortexops.control_plane",
                    authenticated_at=decided_at,
                    authentication_method=str(
                        approval.get("approver_authority") or "cortexops"
                    ),
                ),
                decided_at=decided_at,
                reason=(
                    "CortexOps exact-action permit approved"
                    if approved
                    else "CortexOps exact-action approval rejected"
                ),
                metadata={
                    "remote_approval_id": approval["approval_id"],
                    "action_hash": request.action_hash,
                },
            )
        )


@dataclass(frozen=True, slots=True)
class CortexOpsRecoveryControlResult:
    review: Mapping[str, Any]
    recovery: RecoveryResult | None


@dataclass(slots=True)
class CortexOpsControlledRecoveryExecutor:
    """Execute only an exact, current CortexOps recovery instruction."""

    local: DurableRecoveryExecutor
    control: CortexOpsControlClient

    async def execute(
        self,
        plan: RecoveryPlan,
        *,
        contract: TaskContract[Any, Any],
        preflight_confirmation: RuntimeConfirmation | None = None,
        dry_run: bool = False,
    ) -> CortexOpsRecoveryControlResult:
        try:
            review = self.control.submit_recovery(plan)
            review = self.control.recovery_instruction(str(review["review_id"]))
        except CortexOpsControlUnavailable:
            return CortexOpsRecoveryControlResult(
                review={"status": "unavailable"}, recovery=None
            )
        except CortexOpsControlRejected as error:
            return CortexOpsRecoveryControlResult(
                review={"status": "rejected", "reason": str(error)},
                recovery=None,
            )
        if review.get("status") != "authorized":
            return CortexOpsRecoveryControlResult(review=review, recovery=None)
        if not _same_digest(review.get("plan_hash"), plan.plan_hash):
            raise CortexOpsControlRejected("recovery instruction plan hash mismatch")
        action = plan.actions[0]
        if not _same_digest(review.get("action_hash"), action.action_hash):
            raise CortexOpsControlRejected("recovery instruction action hash mismatch")
        executor = self._local_executor(action.capability)
        initial = await executor.execute(
            plan,
            contract=contract,
            preflight_confirmation=preflight_confirmation,
            dry_run=dry_run,
        )
        if initial.status is RecoveryStatus.AWAITING_APPROVAL:
            self._record_local_approval(plan, review)
            result = await executor.execute(
                plan,
                contract=contract,
                preflight_confirmation=preflight_confirmation,
                dry_run=dry_run,
            )
        else:
            result = initial
        if result.actions and result.actions[0].executor_receipt is not None:
            self.control.send_recovery_result(review, result)
        return CortexOpsRecoveryControlResult(review=review, recovery=result)

    def _local_executor(self, capability: str) -> DurableRecoveryExecutor:
        policy = self.local.policy
        return DurableRecoveryExecutor(
            store=self.local.store,
            registry=self.local.registry,
            policy=RecoveryPolicy(
                allowed_capabilities=policy.allowed_capabilities,
                allowed_task_states=policy.allowed_task_states,
                maximum_risk_level=policy.maximum_risk_level,
                approval_required_capabilities=(
                    policy.approval_required_capabilities | {capability}
                ),
                require_runtime_confirmation=policy.require_runtime_confirmation,
            ),
            handlers=self.local.handlers,
            evidence_providers=self.local.evidence_providers,
            verifier=self.local.verifier,
            event_sink=self.local.event_sink,
            executor_id=self.local.executor_id,
            instance_id=self.local.instance_id,
            clock=self.local.clock,
            id_factory=self.local.id_factory,
        )

    def _record_local_approval(
        self,
        plan: RecoveryPlan,
        review: Mapping[str, Any],
    ) -> None:
        action = plan.actions[0]
        stored = self.local.store.load_approval(f"recovery:{plan.plan_id}:approval")
        if (
            stored.request.task_id != plan.task_id
            or stored.request.target_hash != f"recovery:{plan.plan_hash}"
            or stored.request.required_scope != f"recovery:{action.capability}:execute"
        ):
            raise CortexOpsControlRejected(
                "local approval request is not bound to the governed recovery plan"
            )
        if stored.decision is not None:
            return
        recorder = getattr(self.local.store, "record_approval_decision", None)
        if not callable(recorder):
            raise TypeError("recovery store cannot persist approval decisions")
        now = self.local.clock()
        recorder(
            ApprovalDecision(
                decision_id=f"cortexops:{review['instruction_id']}",
                approval_id=stored.request.approval_id,
                request_hash=stored.request.request_hash,
                approved=True,
                approver=ApproverIdentity(
                    subject=str(review.get("reviewed_by") or "cortexops-operator"),
                    issuer="cortexops.control_plane",
                    authenticated_at=now,
                    authentication_method="cortexops_recovery_review",
                ),
                decided_at=now,
                reason="CortexOps exact-plan recovery instruction authorized",
                metadata={
                    "instruction_id": review["instruction_id"],
                    "plan_hash": plan.plan_hash,
                    "action_hash": action.action_hash,
                },
            )
        )


def _validated_action_decision(
    response: Mapping[str, Any],
    *,
    expected_action_hash: str,
) -> dict[str, Any]:
    """Accept only the exact v1 decision shapes that grant known authority."""

    value = dict(response)
    if value.get("schema_version") != PROTOCOL_VERSION:
        raise CortexOpsControlRejected("unsupported action decision schema version")
    for field_name in ("decision_id", "current_state", "expires_at"):
        if not isinstance(value.get(field_name), str) or not value[field_name].strip():
            raise CortexOpsControlRejected(
                f"action decision omitted required field {field_name}"
            )
    outcome = value.get("outcome")
    if not isinstance(outcome, str) or outcome not in _ACTION_OUTCOMES:
        raise CortexOpsControlRejected("action decision outcome is not recognized")
    if not _same_digest(value.get("action_hash"), expected_action_hash):
        raise CortexOpsControlRejected("decision is bound to another action hash")
    if value.get("trust_boundary") != "authoritative_control":
        raise CortexOpsControlRejected("action decision trust boundary is invalid")
    policy = value.get("policy")
    if (
        not isinstance(policy, Mapping)
        or not isinstance(policy.get("version"), int)
        or not isinstance(policy.get("hash"), str)
        or not policy["hash"]
    ):
        raise CortexOpsControlRejected("action decision policy binding is malformed")
    reason_codes = value.get("reason_codes")
    if not isinstance(reason_codes, list) or any(
        not isinstance(item, str) or not item for item in reason_codes
    ):
        raise CortexOpsControlRejected("action decision reason codes are malformed")

    approval = value.get("approval")
    if outcome != "REQUIRE_APPROVAL":
        if approval is not None:
            raise CortexOpsControlRejected(
                "non-approval decision included an approval response"
            )
        return value
    if not isinstance(approval, Mapping):
        raise CortexOpsControlRejected("approval response is missing or malformed")
    for field_name in ("approval_id", "status"):
        if (
            not isinstance(approval.get(field_name), str)
            or not approval[field_name].strip()
        ):
            raise CortexOpsControlRejected(
                f"approval response omitted required field {field_name}"
            )
    if not _same_digest(approval.get("action_hash"), expected_action_hash):
        raise CortexOpsControlRejected("approval is bound to another action hash")
    approval_status = approval["status"]
    if approval_status not in {
        "pending",
        "approved",
        "denied",
        "rejected",
        "cancelled",
        "expired",
        "consumed",
    }:
        raise CortexOpsControlRejected("approval status is not recognized")
    if approval_status == "approved":
        for field_name in ("permit_id", "permit_hash", "decided_at"):
            if (
                not isinstance(approval.get(field_name), str)
                or not approval[field_name].strip()
            ):
                raise CortexOpsControlRejected(
                    f"approved response omitted required field {field_name}"
                )
    value["approval"] = dict(approval)
    return value


def _policy_facts(
    policy: Mapping[str, Any],
    request: ActionRequest,
    *,
    worker_id: str,
) -> list[dict[str, Any]]:
    rules = policy.get("tool_rules")
    if not isinstance(rules, list):
        raise CortexOpsControlRejected("active policy tool_rules are malformed")
    evaluations: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise CortexOpsControlRejected("active policy rule is malformed")
        match = rule.get("match")
        if not isinstance(match, Mapping):
            match = {}
        conditions: list[dict[str, Any]] = []
        for key, attribute, actual in (
            ("tool_name", "tool.name", request.name),
            ("tool_kind", "tool.kind", "runmantle.mediated"),
            ("agent_id", "agent.id", worker_id),
        ):
            if key in match:
                conditions.append(_condition(attribute, "eq", match[key], actual))
        if "derived_path_glob" in match:
            derived_path = request.metadata.get("derived_path")
            conditions.append(
                _condition(
                    "resource.derived_path",
                    "glob",
                    match["derived_path_glob"],
                    derived_path,
                )
            )
        predicates = match.get("predicates") or []
        if not isinstance(predicates, list):
            raise CortexOpsControlRejected("active policy predicates are malformed")
        for predicate in predicates:
            if not isinstance(predicate, Mapping):
                raise CortexOpsControlRejected("active policy predicate is malformed")
            path = str(predicate.get("path") or "")
            conditions.append(
                _condition(
                    f"params.{path}",
                    str(predicate.get("op") or ""),
                    predicate.get("value"),
                    _resolve(request.input, path),
                )
            )
        evaluations.append(
            {
                "rule_id": str(rule.get("id") or ""),
                "matched": all(item["matched"] for item in conditions),
                "conditions": conditions,
            }
        )
    return evaluations


_MISSING = object()


def _condition(
    attribute: str, operator: str, expected: Any, actual: Any
) -> dict[str, Any]:
    return {
        "attribute": attribute,
        "operator": operator,
        "expected": expected,
        "actual": _fact_value(actual),
        "matched": _matches(operator, actual, expected),
    }


def _fact_value(value: Any) -> dict[str, Any]:
    if value is _MISSING:
        return {"type": "missing"}
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if isinstance(value, (int, float)):
        return {"type": "number", "value": value}
    if isinstance(value, str):
        return {
            "type": "string",
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "length": len(value),
        }
    return {"type": "structured", "sha256": _digest(value)}


def _matches(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "exists":
        return (actual is not _MISSING) is bool(expected)
    if actual is _MISSING:
        return False
    if operator == "eq":
        return bool(actual == expected)
    if operator == "prefix":
        return isinstance(actual, str) and actual.startswith(str(expected))
    if operator == "glob":
        return isinstance(actual, str) and fnmatch.fnmatchcase(actual, str(expected))
    if operator in {"lt", "lte", "gt", "gte"}:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        if isinstance(expected, bool) or not isinstance(expected, (int, float)):
            return False
        return {
            "lt": actual < expected,
            "lte": actual <= expected,
            "gt": actual > expected,
            "gte": actual >= expected,
        }[operator]
    return False


def _resolve(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for component in path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            return _MISSING
        current = current[component]
    return current


def _digest(value: Any) -> str:
    encoded = SafeJsonCodec().dumps(value)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _same_digest(left: Any, right: Any) -> bool:
    return str(left or "").lower().removeprefix("sha256:") == str(
        right or ""
    ).lower().removeprefix("sha256:")


def _aware_datetime(value: Any) -> datetime:
    parsed = (
        value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    )
    if parsed.tzinfo is None:
        raise CortexOpsControlRejected("control timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _http_error_detail(error: HTTPError) -> str:
    try:
        value = json.loads(error.read())
    except (json.JSONDecodeError, OSError):
        return "request rejected"
    return (
        str(value.get("detail") or "request rejected")
        if isinstance(value, dict)
        else "request rejected"
    )


__all__ = [
    "PROTOCOL_VERSION",
    "CortexOpsControlClient",
    "CortexOpsControlError",
    "CortexOpsControlRejected",
    "CortexOpsControlTransport",
    "CortexOpsControlUnavailable",
    "CortexOpsControlledActionExecutor",
    "CortexOpsControlledRecoveryExecutor",
    "CortexOpsRecoveryControlResult",
    "UrllibCortexOpsControlTransport",
]
