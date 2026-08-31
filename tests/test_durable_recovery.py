from __future__ import annotations

import sqlite3
import unittest
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from runmantle import (
    ApprovalDecision,
    ApprovalRevocation,
    ApprovalState,
    ApproverIdentity,
    CapabilityDeclaration,
    CapabilityRegistry,
    ConcurrentUpdateError,
    DurableRecoveryExecutor,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    InMemoryEventSink,
    InvalidTransitionError,
    LifecycleEventType,
    PreActionCapabilityConfirmation,
    PredicateCriterion,
    RecoveryAction,
    RecoveryExecutionReceipt,
    RecoveryExecutorResult,
    RecoveryHandlerRegistration,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryPostcondition,
    RecoveryPrecondition,
    RecoveryReasonCode,
    RecoveryStatus,
    RiskLevel,
    RuleBasedVerifier,
    SQLiteStore,
    StandardCapability,
    TaskContext,
    TaskContract,
    TaskStatus,
    WorkerReport,
)
from runmantle.actions import _stable_provider_configuration
from runmantle.evidence import _establish_evidence_origin

NOW = datetime(2026, 8, 29, 16, 0, tzinfo=UTC)
HANDLER_IDENTITY = "tests.durable_recovery.retry:v1"
HANDLER_CONFIGURATION = {"mode": "test"}


def contract(task_id: str) -> TaskContract[dict[str, Any], dict[str, Any]]:
    return TaskContract(
        task_id=task_id,
        objective="Recover a task and independently confirm service health.",
        input={},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="worker-output",
                description="The original output was structurally successful.",
                field_path="ok",
                expected=True,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type="service_health",
                description="Independent service health observation.",
            ),
        ),
        allowed_capabilities=frozenset({StandardCapability.RETRY}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}-retry",
    )


def worker() -> FunctionWorker[dict[str, Any], dict[str, Any]]:
    async def execute(
        task: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del task, context
        return WorkerReport.completed({"ok": True})

    return FunctionWorker(
        id="recovery-worker",
        name="Recovery fixture worker",
        role="test",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name=StandardCapability.RETRY,
                description="Retry through the recovery boundary.",
            ),
        ),
        handler=execute,
    )


def precondition(
    plan: RecoveryPlan,
    action: RecoveryAction,
    task_contract: TaskContract[Any, Any],
) -> bool:
    return (
        plan.task_id == task_contract.task_id
        and action.idempotency_key == task_contract.idempotency_key
    )


class HealthProvider:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    async def acquire(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: Any,
    ) -> EvidenceItem:
        del action, receipt
        if self.fail:
            raise RuntimeError("health endpoint remained unavailable")
        return EvidenceItem(
            evidence_id=f"{plan.plan_id}-health",
            type="service_health",
            source="health-api",
            collected_at=NOW,
            payload={"healthy": True},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
            provenance={"recovery_plan_id": plan.plan_id},
        )


@dataclass(slots=True)
class ConfigurableHealthProvider:
    endpoint: str

    async def acquire(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: Any,
    ) -> EvidenceItem:
        del action, receipt
        return EvidenceItem(
            evidence_id=f"{plan.plan_id}-configured-health",
            type="service_health",
            source=self.endpoint,
            collected_at=NOW,
            payload={"healthy": True},
        )


def plan(
    task_contract: TaskContract[Any, Any],
    *,
    provider: HealthProvider | ConfigurableHealthProvider | None = None,
    approval_required: bool = True,
) -> RecoveryPlan:
    action = RecoveryAction(
        action_id=f"{task_contract.task_id}-retry-action",
        capability=StandardCapability.RETRY,
        idempotency_key=task_contract.idempotency_key,
        reason="Retry after the health evidence was missing.",
        parameters={"attempt": 2},
        handler_identity=HANDLER_IDENTITY,
        handler_configuration=HANDLER_CONFIGURATION,
    )
    return RecoveryPlan(
        plan_id=f"{task_contract.task_id}-recovery",
        task_id=task_contract.task_id,
        actions=(action,),
        proposed_by="recovery-coordinator",
        failure_diagnosis="The worker completed but service health was not observed.",
        context_reference=f"task:{task_contract.task_id}:checkpoint:reported-output",
        risk_level=RiskLevel.LOW,
        approval_required=approval_required,
        preconditions=(
            RecoveryPrecondition(
                name="same-idempotency-boundary",
                description="The retry remains bound to the original contract.",
                evaluator=precondition,
            ),
        ),
        postconditions=(
            RecoveryPostcondition(
                name="service-is-healthy",
                description="Acquire health independently after retry.",
                provider=provider or HealthProvider(),
                evidence_type="service_health",
            ),
        ),
        compensation_id="application.rollback_retry",
        created_at=NOW,
    )


def confirmation(recovery_plan: RecoveryPlan) -> PreActionCapabilityConfirmation:
    action = recovery_plan.actions[0]
    return PreActionCapabilityConfirmation(
        confirmation_id=f"{recovery_plan.plan_id}-preflight",
        action_id=action.action_id,
        capability=action.capability,
        idempotency_key=action.idempotency_key,
        supported=True,
        safe=True,
        confirmed_at=NOW,
        confirmed_by="local-runtime-registry",
        reason="The retry handler is installed and the operation is idempotent.",
        target_hash=action.action_hash,
    )


def policy() -> RecoveryPolicy:
    return RecoveryPolicy(
        allowed_capabilities=frozenset({StandardCapability.RETRY}),
        allowed_task_states=frozenset(
            {TaskStatus.AWAITING_EVIDENCE, TaskStatus.FAILED}
        ),
        maximum_risk_level=RiskLevel.MEDIUM,
        require_runtime_confirmation=True,
    )


async def awaiting_task(path: Path, task_id: str) -> TaskContract[Any, Any]:
    task_contract = contract(task_id)
    result = await DurableRuntime(
        database_path=path,
        verifier=RuleBasedVerifier(clock=lambda: NOW),
        clock=lambda: NOW,
    ).execute(worker(), task_contract)
    if result.status is not TaskStatus.AWAITING_EVIDENCE:
        raise AssertionError("fixture task did not reach AWAITING_EVIDENCE")
    return task_contract


def executor(
    store: SQLiteStore,
    calls: list[str],
    *,
    now: datetime = NOW,
    instance_id: str = "recovery-process",
    handler_identity: str = HANDLER_IDENTITY,
    handler_configuration: dict[str, Any] | None = None,
    handler_label: str | None = None,
) -> Any:
    async def handler(
        action: RecoveryAction, task_contract: TaskContract[Any, Any]
    ) -> Any:
        call = f"{task_contract.task_id}:{action.action_id}"
        calls.append(f"{handler_label}:{call}" if handler_label else call)
        return {"retry_started": True}

    class RegisteredExecutor:
        async def execute(
            self,
            recovery_plan: RecoveryPlan,
            **kwargs: Any,
        ) -> Any:
            registrations = tuple(
                EvidenceProviderRegistration(
                    provider=postcondition.provider,
                    provider_identity=str(postcondition.provider_identity),
                    provider_configuration=_stable_provider_configuration(
                        postcondition.provider
                    ),
                    trust_level=EvidenceTrustLevel.INDEPENDENT,
                    acquisition_method=(EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER),
                )
                for postcondition in recovery_plan.postconditions
            )
            delegate = DurableRecoveryExecutor(
                store=store,
                registry=CapabilityRegistry.with_standard_recovery_capabilities(),
                policy=policy(),
                handlers={
                    StandardCapability.RETRY: RecoveryHandlerRegistration(
                        handler=handler,
                        handler_identity=handler_identity,
                        handler_configuration=(
                            HANDLER_CONFIGURATION
                            if handler_configuration is None
                            else handler_configuration
                        ),
                    )
                },
                evidence_providers=EvidenceProviderRegistry(registrations),
                verifier=RuleBasedVerifier(clock=lambda: now),
                clock=lambda: now,
                id_factory=lambda: "recovery-receipt",
                instance_id=instance_id,
            )
            return await delegate.execute(recovery_plan, **kwargs)

    return RegisteredExecutor()


def approve(store: SQLiteStore, recovery_plan: RecoveryPlan) -> ApprovalDecision:
    stored = store.load_approval(f"recovery:{recovery_plan.plan_id}:approval")
    decision = ApprovalDecision(
        decision_id=f"{recovery_plan.plan_id}-decision",
        approval_id=stored.request.approval_id,
        request_hash=stored.request.request_hash,
        approved=True,
        approver=ApproverIdentity(
            subject="operator@example.test",
            issuer="test-auth-boundary",
            authenticated_at=NOW,
            authentication_method="test-mfa",
            claims={"role": "incident-commander"},
        ),
        decided_at=NOW,
        reason="Reviewed the exact recovery plan and scope.",
        metadata={"ticket": "INC-42"},
    )
    store.record_approval_decision(decision)
    return decision


class DurableApprovalAndRecoveryTest(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_recovery_transition_rolls_back(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "invalid-recovery-transition")
            recovery_plan = plan(task_contract, approval_required=False)
            store = SQLiteStore(path)
            state = store.save_recovery_state(
                recovery_plan,
                status=RecoveryStatus.PLANNED.value,
                occurred_at=NOW,
            )

            with self.assertRaises(InvalidTransitionError):
                store.save_recovery_state(
                    recovery_plan,
                    status=RecoveryStatus.VERIFIED.value,
                    occurred_at=NOW,
                    expected_version=state.version,
                )

            persisted = store.load_recovery_state(recovery_plan.plan_id)
            self.assertEqual(
                persisted.status if persisted else None,
                RecoveryStatus.PLANNED.value,
            )
            self.assertEqual(persisted.version if persisted else None, state.version)

    async def test_negative_preflight_confirmation_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "negative-preflight")
            recovery_plan = plan(task_contract, approval_required=False)
            calls: list[str] = []

            result = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=replace(
                    confirmation(recovery_plan),
                    safe=False,
                    reason="The runtime preflight rejected this action.",
                ),
            )

            self.assertEqual(result.status, RecoveryStatus.BLOCKED)
            self.assertEqual(
                result.actions[0].reason.code,
                RecoveryReasonCode.PREFLIGHT_CONFIRMATION_REJECTED,
            )
            self.assertEqual(calls, [])

    async def test_executor_reported_failure_is_not_unknown_or_success(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "executor-failure")
            recovery_plan = plan(task_contract, approval_required=False)
            sink = InMemoryEventSink()

            async def failed_handler(
                action: RecoveryAction,
                supplied_contract: TaskContract[Any, Any],
            ) -> RecoveryExecutorResult:
                del action, supplied_contract
                return RecoveryExecutorResult(
                    succeeded=False,
                    message="The executor rejected the retry.",
                )

            result = await DurableRecoveryExecutor(
                store=SQLiteStore(path),
                registry=CapabilityRegistry.with_standard_recovery_capabilities(),
                policy=policy(),
                handlers={
                    StandardCapability.RETRY: RecoveryHandlerRegistration(
                        handler=failed_handler,
                        handler_identity=HANDLER_IDENTITY,
                        handler_configuration=HANDLER_CONFIGURATION,
                    )
                },
                verifier=RuleBasedVerifier(clock=lambda: NOW),
                event_sink=sink,
                clock=lambda: NOW,
                id_factory=lambda: "failed-recovery-receipt",
                instance_id="failed-recovery-process",
            ).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )

            self.assertEqual(result.status, RecoveryStatus.FAILED)
            self.assertTrue(result.executed)
            self.assertFalse(result.succeeded)
            self.assertIn(
                LifecycleEventType.RECOVERY_EXECUTION_FAILED,
                {event.event_type for event in sink.snapshot()},
            )
            self.assertEqual(
                SQLiteStore(path).load_task(task_contract.task_id).status,
                TaskStatus.AWAITING_EVIDENCE,
            )

    async def test_restart_after_executor_receipt_continues_postconditions(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "receipt-restart")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            first_store = SQLiteStore(path)

            waiting = await executor(first_store, calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            self.assertEqual(waiting.status, RecoveryStatus.AWAITING_APPROVAL)
            approve(first_store, recovery_plan)
            approval = first_store.load_approval(
                f"recovery:{recovery_plan.plan_id}:approval"
            )
            state = first_store.load_recovery_state(recovery_plan.plan_id)
            assert state is not None
            state = first_store.save_recovery_state(
                recovery_plan,
                status=RecoveryStatus.AUTHORIZED.value,
                occurred_at=NOW,
                expected_version=state.version,
            )
            state, _ = first_store.claim_recovery_execution(
                recovery_plan,
                expected_version=state.version,
                owner_id="process-before-restart",
                occurred_at=NOW,
                approval_id=approval.request.approval_id,
                approval_request_hash=approval.request.request_hash,
                approval_scope=f"recovery:{StandardCapability.RETRY}:execute",
            )
            first_store.finish_recovery_execution(
                recovery_plan,
                expected_version=state.version,
                owner_id="process-before-restart",
                receipt=RecoveryExecutionReceipt(
                    receipt_id="persisted-receipt",
                    plan_id=recovery_plan.plan_id,
                    action_id=recovery_plan.actions[0].action_id,
                    action_hash=recovery_plan.actions[0].action_hash,
                    executor_id="external-recovery-executor",
                    status=RecoveryStatus.EXECUTOR_SUCCEEDED,
                    started_at=NOW,
                    finished_at=NOW,
                    output={"retry_started": True},
                ),
            )

            resumed = await executor(
                SQLiteStore(path),
                calls,
                instance_id="process-after-restart",
            ).execute(recovery_plan, contract=task_contract)

            self.assertEqual(resumed.status, RecoveryStatus.VERIFIED)
            self.assertEqual(calls, [])
            self.assertEqual(
                SQLiteStore(path)
                .load_approval(approval.request.approval_id)
                .state_at(NOW),
                ApprovalState.CONSUMED,
            )

    async def test_failed_task_changes_only_after_recovery_postcondition(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = TaskContract[None, dict[str, bool]](
                task_id="failed-then-recovered",
                objective="Recover from a failed health observation.",
                input=None,
                acceptance_criteria=(
                    PredicateCriterion(
                        name="any-healthy-observation",
                        description="At least one health observation must be healthy.",
                        predicate=lambda output, evidence: any(
                            item.payload is not None
                            and item.payload.get("healthy") is True
                            for item in evidence.of_type("service_health")
                        ),
                    ),
                ),
                required_evidence=(
                    EvidenceRequirement(
                        evidence_type="service_health",
                        description="A service health observation.",
                    ),
                ),
                allowed_capabilities=frozenset({StandardCapability.RETRY}),
                risk_level=RiskLevel.LOW,
                timeout=timedelta(seconds=2),
                idempotency_key="failed-then-recovered-retry",
            )

            async def report_unhealthy(
                task: TaskContract[None, dict[str, bool]],
                context: TaskContext,
            ) -> WorkerReport[dict[str, bool]]:
                del task
                context.evidence.record(
                    "service_health",
                    {"healthy": False},
                    source="initial-health-api",
                    evidence_id="initial-unhealthy",
                )
                return WorkerReport.completed({"completed": True})

            unhealthy_worker = FunctionWorker(
                id="unhealthy-worker",
                name="Unhealthy worker",
                role="test",
                version="1.0.0",
                capabilities=(
                    CapabilityDeclaration(
                        name=StandardCapability.RETRY,
                        description="Retry the failed health check.",
                    ),
                ),
                handler=report_unhealthy,
            )
            initial_runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(clock=lambda: NOW),
                clock=lambda: NOW,
            )
            awaiting = await initial_runtime.execute(unhealthy_worker, task_contract)
            self.assertEqual(awaiting.status, TaskStatus.AWAITING_EVIDENCE)
            initial_runtime.store.record_evidence(
                task_contract.task_id,
                _establish_evidence_origin(
                    EvidenceItem(
                        evidence_id="runtime-unhealthy",
                        type="service_health",
                        source="runtime-health-api",
                        collected_at=NOW,
                        payload={"healthy": False},
                    ),
                    boundary="durable_recovery_test_runtime",
                    provider_identity="tests.initial_health:v1",
                    provider_configuration={"fixture": True},
                    trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                    acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                ),
            )
            initial = await initial_runtime.resume(
                task_contract.task_id,
                contract=task_contract,
            )
            self.assertEqual(initial.status, TaskStatus.FAILED)
            recovery_plan = plan(task_contract, approval_required=False)
            calls: list[str] = []

            result = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )

            self.assertEqual(result.status, RecoveryStatus.VERIFIED)
            self.assertEqual(
                SQLiteStore(path).load_task(task_contract.task_id).status,
                TaskStatus.VERIFIED,
            )

    async def test_persisted_pause_decision_and_restart_resume_to_verified(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "approval-resume")
            recovery_plan = plan(task_contract)
            calls: list[str] = []

            waiting = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            self.assertEqual(waiting.status, RecoveryStatus.AWAITING_APPROVAL)
            self.assertEqual(calls, [])
            self.assertEqual(
                SQLiteStore(path).load_task(task_contract.task_id).status,
                TaskStatus.AWAITING_EVIDENCE,
            )

            approve(SQLiteStore(path), recovery_plan)
            resumed = await executor(
                SQLiteStore(path),
                calls,
                instance_id="second-process",
            ).execute(recovery_plan, contract=task_contract)

            self.assertEqual(resumed.status, RecoveryStatus.VERIFIED)
            self.assertTrue(resumed.succeeded)
            self.assertEqual(
                calls, [f"{task_contract.task_id}:{recovery_plan.actions[0].action_id}"]
            )
            self.assertEqual(
                SQLiteStore(path).load_task(task_contract.task_id).status,
                TaskStatus.VERIFIED,
            )
            approval = SQLiteStore(path).load_approval(
                f"recovery:{recovery_plan.plan_id}:approval"
            )
            self.assertEqual(approval.consumed_by, f"recovery:{recovery_plan.plan_id}")

    async def test_crash_after_execution_claim_becomes_unknown_after_restart(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "crash-recovery")
            recovery_plan = plan(task_contract, approval_required=False)
            store = SQLiteStore(path)
            store.save_runtime_confirmation(
                task_contract.task_id,
                confirmation(recovery_plan),
            )
            state = store.save_recovery_state(
                recovery_plan,
                status=RecoveryStatus.PLANNED.value,
                occurred_at=NOW,
            )
            state = store.save_recovery_state(
                recovery_plan,
                status=RecoveryStatus.AUTHORIZED.value,
                occurred_at=NOW,
                expected_version=state.version,
            )
            store.claim_recovery_execution(
                recovery_plan,
                expected_version=state.version,
                owner_id="crashed-process",
                occurred_at=NOW,
            )
            calls: list[str] = []

            result = await executor(
                SQLiteStore(path),
                calls,
                instance_id="restarted-process",
            ).execute(recovery_plan, contract=task_contract)

            self.assertEqual(result.status, RecoveryStatus.UNKNOWN)
            self.assertEqual(calls, [])
            self.assertEqual(
                SQLiteStore(path).load_task(task_contract.task_id).status,
                TaskStatus.AWAITING_EVIDENCE,
            )

    async def test_expired_approval_cannot_execute_recovery(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "expired-approval")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            stored = SQLiteStore(path).load_approval(
                f"recovery:{recovery_plan.plan_id}:approval"
            )
            late = NOW + timedelta(days=2)
            decision = ApprovalDecision(
                decision_id="late-decision",
                approval_id=stored.request.approval_id,
                request_hash=stored.request.request_hash,
                approved=True,
                approver=ApproverIdentity(
                    subject="late-operator",
                    issuer="test-auth-boundary",
                    authenticated_at=late,
                    authentication_method="test-mfa",
                ),
                decided_at=late,
                reason="Too late.",
            )

            with self.assertRaises(InvalidTransitionError):
                SQLiteStore(path).record_approval_decision(decision)
            self.assertEqual(calls, [])

    async def test_mismatched_hash_and_modified_plan_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "hash-mismatch")
            recovery_plan = plan(task_contract)
            await executor(SQLiteStore(path), []).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            stored = SQLiteStore(path).load_approval(
                f"recovery:{recovery_plan.plan_id}:approval"
            )
            mismatched = ApprovalDecision(
                decision_id="wrong-hash",
                approval_id=stored.request.approval_id,
                request_hash="sha256:not-the-request",
                approved=True,
                approver=ApproverIdentity(
                    subject="operator",
                    issuer="test-auth-boundary",
                    authenticated_at=NOW,
                    authentication_method="test-mfa",
                ),
                decided_at=NOW,
                reason="Wrong target.",
            )
            with self.assertRaises(InvalidTransitionError):
                SQLiteStore(path).record_approval_decision(mismatched)

            modified_action = replace(
                recovery_plan.actions[0],
                parameters={"attempt": 3},
            )
            modified_plan = replace(recovery_plan, actions=(modified_action,))
            with self.assertRaises(ConcurrentUpdateError):
                await executor(SQLiteStore(path), []).execute(
                    modified_plan,
                    contract=task_contract,
                )

    async def test_approved_handler_a_cannot_execute_handler_b(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "handler-substitution")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            waiting = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            self.assertEqual(waiting.status, RecoveryStatus.AWAITING_APPROVAL)
            approve(SQLiteStore(path), recovery_plan)

            with self.assertRaisesRegex(ValueError, "handler identity"):
                await executor(
                    SQLiteStore(path),
                    calls,
                    handler_identity="tests.durable_recovery.retry_b:v1",
                    handler_label="handler-b",
                ).execute(recovery_plan, contract=task_contract)
            self.assertEqual(calls, [])

    async def test_changed_handler_configuration_invalidates_approval(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "handler-config-drift")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            approve(SQLiteStore(path), recovery_plan)

            with self.assertRaisesRegex(ValueError, "handler configuration"):
                await executor(
                    SQLiteStore(path),
                    calls,
                    handler_configuration={"mode": "changed"},
                ).execute(recovery_plan, contract=task_contract)
            self.assertEqual(calls, [])

    async def test_changed_provider_configuration_invalidates_approval(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "provider-config-drift")
            provider = ConfigurableHealthProvider("https://health-a.invalid")
            recovery_plan = plan(task_contract, provider=provider)
            calls: list[str] = []
            await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            approve(SQLiteStore(path), recovery_plan)
            provider.endpoint = "https://health-b.invalid"

            with self.assertRaisesRegex(ValueError, "provider configuration"):
                await executor(SQLiteStore(path), calls).execute(
                    recovery_plan,
                    contract=task_contract,
                )
            self.assertEqual(calls, [])

    async def test_exact_execution_manifest_resumes_after_restart(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "manifest-restart")
            recovery_plan = plan(
                task_contract,
                provider=ConfigurableHealthProvider("https://health-a.invalid"),
            )
            calls: list[str] = []
            await executor(SQLiteStore(path), calls, instance_id="process-one").execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            approve(SQLiteStore(path), recovery_plan)

            resumed = await executor(
                SQLiteStore(path), calls, instance_id="process-two"
            ).execute(recovery_plan, contract=task_contract)

            self.assertEqual(resumed.status, RecoveryStatus.VERIFIED)
            self.assertEqual(len(calls), 1)

    async def test_exact_manifest_recovery_remains_at_most_once(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "manifest-at-most-once")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            first = executor(SQLiteStore(path), calls, instance_id="process-one")
            await first.execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            approve(SQLiteStore(path), recovery_plan)
            completed = await executor(
                SQLiteStore(path), calls, instance_id="process-two"
            ).execute(recovery_plan, contract=task_contract)
            duplicate = await executor(
                SQLiteStore(path), calls, instance_id="process-three"
            ).execute(recovery_plan, contract=task_contract)

            self.assertEqual(completed.status, RecoveryStatus.VERIFIED)
            self.assertEqual(duplicate.status, RecoveryStatus.DUPLICATE_PREVENTED)
            self.assertEqual(len(calls), 1)

    async def test_duplicate_decision_and_recovery_do_not_repeat_effects(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "duplicate-recovery")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            decision = approve(SQLiteStore(path), recovery_plan)
            duplicate, event = SQLiteStore(path).record_approval_decision(decision)
            self.assertIsNone(event)
            self.assertEqual(duplicate.decision, decision)

            first = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
            )
            duplicate_recovery = await executor(
                SQLiteStore(path),
                calls,
                instance_id="duplicate-process",
            ).execute(recovery_plan, contract=task_contract)

            self.assertEqual(first.status, RecoveryStatus.VERIFIED)
            self.assertEqual(
                duplicate_recovery.status,
                RecoveryStatus.DUPLICATE_PREVENTED,
            )
            self.assertEqual(len(calls), 1)

    async def test_failed_postcondition_never_mutates_original_task(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "failed-postcondition")
            recovery_plan = plan(
                task_contract,
                provider=HealthProvider(fail=True),
                approval_required=False,
            )
            calls: list[str] = []

            result = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )

            self.assertEqual(result.status, RecoveryStatus.POSTCONDITION_FAILED)
            self.assertFalse(result.succeeded)
            self.assertEqual(len(calls), 1)
            self.assertEqual(
                SQLiteStore(path).load_task(task_contract.task_id).status,
                TaskStatus.AWAITING_EVIDENCE,
            )

    async def test_revoked_approval_cannot_resume_recovery(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = await awaiting_task(path, "revoked-approval")
            recovery_plan = plan(task_contract)
            calls: list[str] = []
            await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=confirmation(recovery_plan),
            )
            approve(SQLiteStore(path), recovery_plan)
            stored = SQLiteStore(path).load_approval(
                f"recovery:{recovery_plan.plan_id}:approval"
            )
            SQLiteStore(path).revoke_approval(
                ApprovalRevocation(
                    revocation_id="operator-revocation",
                    approval_id=stored.request.approval_id,
                    request_hash=stored.request.request_hash,
                    revoked_by=ApproverIdentity(
                        subject="operator@example.test",
                        issuer="test-auth-boundary",
                        authenticated_at=NOW,
                        authentication_method="test-mfa",
                    ),
                    revoked_at=NOW,
                    reason="Conditions changed before execution.",
                )
            )

            resumed = await executor(SQLiteStore(path), calls).execute(
                recovery_plan,
                contract=task_contract,
            )

            self.assertEqual(resumed.status, RecoveryStatus.AWAITING_APPROVAL)
            self.assertEqual(calls, [])
            self.assertEqual(
                SQLiteStore(path)
                .load_approval(stored.request.approval_id)
                .state_at(NOW),
                ApprovalState.REVOKED,
            )

    async def test_schema_three_legacy_approval_migrates_without_new_authority(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            task_contract = contract("legacy-approval")
            legacy = SQLiteStore(path, target_schema_version=3)
            legacy.create_task(
                task_contract,
                correlation_id="legacy-correlation",
                worker_id="legacy-worker",
                occurred_at=NOW,
            )
            with sqlite3.connect(path) as connection:
                connection.execute(
                    """
                    INSERT INTO approvals(
                        approval_id, task_id, approval_key, approved, approved_by,
                        reason, created_at, decided_at, capability, idempotency_key
                    ) VALUES(?, ?, ?, 1, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (
                        "legacy-approval-id",
                        task_contract.task_id,
                        "legacy-release-key",
                        "legacy-operator",
                        "Legacy approval.",
                        NOW.isoformat(),
                        NOW.isoformat(),
                    ),
                )

            migrated = SQLiteStore(path)
            stored = migrated.load_approval("legacy-approval-id")

            self.assertEqual(migrated.schema_version, 7)
            self.assertFalse(stored.request.one_time_use)
            self.assertEqual(stored.request.required_scope, "legacy.approval")
            self.assertIsNotNone(stored.decision)
            self.assertEqual(
                stored.decision.approver.issuer if stored.decision else None,
                "legacy-unverified",
            )


if __name__ == "__main__":
    unittest.main()
