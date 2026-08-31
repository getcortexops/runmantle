"""Persist a recovery pause, stop, and resume it from a second local process."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from runmantle import (
    ApprovalDecision,
    ApproverIdentity,
    CapabilityDeclaration,
    CapabilityRegistry,
    DurableRecoveryExecutor,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    PreActionCapabilityConfirmation,
    RecoveryAction,
    RecoveryHandlerRegistration,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryPostcondition,
    RecoveryPrecondition,
    RiskLevel,
    RuleBasedVerifier,
    SQLiteStore,
    StandardCapability,
    TaskContext,
    TaskContract,
    TaskStatus,
    WorkerReport,
)

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


class HealthEvidenceProvider:
    async def acquire(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: Any,
    ) -> EvidenceItem:
        del action, receipt
        return EvidenceItem(
            evidence_id=f"{plan.plan_id}-health",
            type="service_health",
            source="example-health-api",
            collected_at=NOW,
            payload={"healthy": True},
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        )


def build_contract() -> TaskContract[None, dict[str, bool]]:
    return TaskContract(
        task_id="durable-recovery-demo",
        objective="Verify a retry using independently acquired service health.",
        input=None,
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="worker-completed",
                description="The worker output is structurally complete.",
                field_path="completed",
                expected=True,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type="service_health",
                description="Health observed outside the recovery handler.",
                minimum_trust_level=EvidenceTrustLevel.INDEPENDENT,
            ),
        ),
        allowed_capabilities=frozenset({StandardCapability.RETRY}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key="durable-recovery-demo-retry",
    )


def build_worker() -> FunctionWorker[None, dict[str, bool]]:
    async def execute(
        task: TaskContract[None, dict[str, bool]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, bool]]:
        del task, context
        return WorkerReport.completed({"completed": True})

    return FunctionWorker(
        id="durable-recovery-demo-worker",
        name="Durable recovery demo worker",
        role="example",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name=StandardCapability.RETRY,
                description="Retry through the example recovery handler.",
            ),
        ),
        handler=execute,
    )


def build_plan(contract: TaskContract[Any, Any]) -> RecoveryPlan:
    action = RecoveryAction(
        action_id="durable-retry-action",
        capability=StandardCapability.RETRY,
        idempotency_key=contract.idempotency_key,
        reason="Retry after health evidence was unavailable.",
        parameters={"attempt": 2},
        handler_identity="runmantle.example.retry:v1",
        handler_configuration={"mode": "local_example"},
    )
    return RecoveryPlan(
        plan_id="durable-recovery-plan",
        task_id=contract.task_id,
        actions=(action,),
        proposed_by="example-recovery-coordinator",
        failure_diagnosis="The reported output lacks external health evidence.",
        context_reference=f"task:{contract.task_id}:reported-output",
        approval_required=True,
        preconditions=(
            RecoveryPrecondition(
                name="same-task-idempotency-key",
                description="Retry remains bound to the original contract.",
                evaluator=lambda plan, action, task: (
                    plan.task_id == task.task_id
                    and action.idempotency_key == task.idempotency_key
                ),
            ),
        ),
        postconditions=(
            RecoveryPostcondition(
                name="service-health",
                description="Acquire health after the handler returns.",
                provider=HealthEvidenceProvider(),
                evidence_type="service_health",
            ),
        ),
        compensation_id="example.rollback_retry",
        created_at=NOW,
    )


def recovery_executor(
    database: Path,
    executions: list[str],
    *,
    instance_id: str,
) -> DurableRecoveryExecutor:
    async def retry(
        action: RecoveryAction,
        contract: TaskContract[Any, Any],
    ) -> dict[str, bool]:
        executions.append(f"{contract.task_id}:{action.action_id}")
        return {"retry_started": True}

    return DurableRecoveryExecutor(
        store=SQLiteStore(database),
        registry=CapabilityRegistry.with_standard_recovery_capabilities(),
        policy=RecoveryPolicy(
            allowed_capabilities=frozenset({StandardCapability.RETRY}),
            allowed_task_states=frozenset({TaskStatus.AWAITING_EVIDENCE}),
            maximum_risk_level=RiskLevel.LOW,
            require_runtime_confirmation=True,
        ),
        handlers={
            StandardCapability.RETRY: RecoveryHandlerRegistration(
                handler=retry,
                handler_identity="runmantle.example.retry:v1",
                handler_configuration={"mode": "local_example"},
            )
        },
        verifier=RuleBasedVerifier(clock=lambda: NOW),
        clock=lambda: NOW,
        instance_id=instance_id,
        id_factory=lambda: "durable-recovery-receipt",
    )


async def main() -> None:
    with TemporaryDirectory() as directory:
        database = Path(directory) / "runmantle.db"
        contract = build_contract()
        initial = await DurableRuntime(
            database_path=database,
            verifier=RuleBasedVerifier(clock=lambda: NOW),
            clock=lambda: NOW,
        ).execute(build_worker(), contract)
        plan = build_plan(contract)
        action = plan.actions[0]
        executions: list[str] = []

        first_process = recovery_executor(
            database,
            executions,
            instance_id="recovery-process-1",
        )
        paused = await first_process.execute(
            plan,
            contract=contract,
            preflight_confirmation=PreActionCapabilityConfirmation(
                confirmation_id="durable-recovery-preflight",
                action_id=action.action_id,
                capability=action.capability,
                idempotency_key=action.idempotency_key,
                supported=True,
                safe=True,
                confirmed_at=NOW,
                confirmed_by="example-runtime",
                reason="The local retry handler is installed and idempotent.",
                target_hash=action.action_hash,
            ),
        )

        # The first executor may now disappear. A separate application boundary
        # authenticates the approver and writes only the exact pending request.
        store = SQLiteStore(database)
        pending = store.load_approval(f"recovery:{plan.plan_id}:approval")
        store.record_approval_decision(
            ApprovalDecision(
                decision_id="durable-recovery-decision",
                approval_id=pending.request.approval_id,
                request_hash=pending.request.request_hash,
                approved=True,
                approver=ApproverIdentity(
                    subject="operator@example.test",
                    issuer="example-auth-boundary",
                    authenticated_at=NOW,
                    authentication_method="example-mfa",
                ),
                decided_at=NOW,
                reason="Approved the exact persisted recovery plan.",
            )
        )

        second_process = recovery_executor(
            database,
            executions,
            instance_id="recovery-process-2",
        )
        resumed = await second_process.execute(plan, contract=contract)

        print(f"initial_task={initial.status.value}")
        print(f"persisted_pause={paused.status.value}")
        print(f"resumed_recovery={resumed.status.value}")
        print(f"executions={len(executions)}")
        final = SQLiteStore(database).load_task(contract.task_id)
        print(f"final_task={final.status.value}")


if __name__ == "__main__":
    asyncio.run(main())
