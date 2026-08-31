from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from runmantle import (
    CapabilityDeclaration,
    CapabilityRegistry,
    EvidenceRequirement,
    FunctionWorker,
    InMemoryEventSink,
    InMemoryRecoveryExecutor,
    InMemoryRuntime,
    LifecycleEventType,
    PredicateCriterion,
    RecoveryAction,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryStatus,
    RiskLevel,
    RuleBasedVerifier,
    RuntimeConfirmation,
    StandardCapability,
    TaskContext,
    TaskContract,
    TaskStatus,
    VerificationStatus,
    WorkerReport,
    WorkerReportedStatus,
)

CONFIRMED_AT = datetime(2026, 8, 26, 10, 0, tzinfo=UTC)


class CompleteFlowTest(unittest.IsolatedAsyncioTestCase):
    async def test_execution_verification_and_confirmed_recovery(self) -> None:
        events = InMemoryEventSink()

        async def execute(
            task: TaskContract[int, int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            context.require_capability("calculate")
            context.evidence.record(
                "calculation",
                {"input": task.input, "output": 41},
                source="complete-flow-worker",
                evidence_id="complete-flow-evidence",
            )
            return WorkerReport.completed(41)

        contract = TaskContract[int, int](
            task_id="complete-flow-task",
            objective="Return exactly 42, then recover safely if verification fails.",
            input=21,
            acceptance_criteria=(
                PredicateCriterion(
                    name="answer-is-42",
                    description="The reported output must equal 42.",
                    predicate=lambda output, evidence: output == 42,
                ),
            ),
            required_evidence=(
                EvidenceRequirement(
                    "calculation",
                    "The input and reported calculation output.",
                ),
            ),
            allowed_capabilities=frozenset({"calculate", StandardCapability.RETRY}),
            risk_level=RiskLevel.LOW,
            timeout=timedelta(seconds=1),
            idempotency_key="complete-flow-key",
        )
        worker = FunctionWorker[int, int](
            id="complete-flow-worker",
            name="Complete flow worker",
            role="end-to-end-test",
            version="1.0.0",
            capabilities=(
                CapabilityDeclaration(
                    name="calculate",
                    description="Produce an in-memory calculation.",
                ),
            ),
            handler=execute,
        )

        task_result = await InMemoryRuntime(
            verifier=RuleBasedVerifier(),
            event_sink=events,
        ).execute(
            worker,
            contract,
            correlation_id="complete-flow-correlation",
        )

        self.assertEqual(task_result.reported_status, WorkerReportedStatus.COMPLETED)
        self.assertEqual(len(task_result.evidence), 1)
        self.assertEqual(task_result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertIsNotNone(task_result.final_verification_result)
        self.assertEqual(
            task_result.final_verification_result.status
            if task_result.final_verification_result
            else None,
            VerificationStatus.AWAITING_EVIDENCE,
        )

        action = RecoveryAction(
            action_id="retry-complete-flow",
            capability=StandardCapability.RETRY,
            idempotency_key=contract.idempotency_key,
            reason="Retry after deterministic verification failure.",
        )
        plan = RecoveryPlan(
            plan_id="complete-flow-recovery",
            task_id=contract.task_id,
            actions=(action,),
            proposed_by=worker.id,
        )
        recovered: list[str] = []

        async def retry_handler(
            recovery_action: RecoveryAction,
            recovery_contract: TaskContract[Any, Any],
        ) -> None:
            recovered.append(f"{recovery_contract.task_id}:{recovery_action.action_id}")

        recovery = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=RecoveryPolicy(
                allowed_capabilities=frozenset({StandardCapability.RETRY}),
                allowed_task_states=frozenset({TaskStatus.AWAITING_EVIDENCE}),
                maximum_risk_level=RiskLevel.LOW,
                require_runtime_confirmation=True,
            ),
            handlers={StandardCapability.RETRY: retry_handler},
            event_sink=events,
        )

        blocked = await recovery.execute(
            plan,
            contract=contract,
            task_state=task_result.status,
            correlation_id=task_result.correlation_id,
        )
        confirmed = await recovery.execute(
            plan,
            contract=contract,
            task_state=task_result.status,
            confirmations=(
                RuntimeConfirmation(
                    confirmation_id="complete-flow-confirmation",
                    action_id=action.action_id,
                    capability=action.capability,
                    idempotency_key=action.idempotency_key,
                    supported=True,
                    safe=True,
                    confirmed_at=CONFIRMED_AT,
                    confirmed_by="complete-flow-runtime",
                    reason="The injected retry handler is installed and safe.",
                ),
            ),
            correlation_id=task_result.correlation_id,
        )

        self.assertEqual(
            blocked.status,
            RecoveryStatus.AWAITING_RUNTIME_CONFIRMATION,
        )
        self.assertEqual(confirmed.status, RecoveryStatus.RUNTIME_CONFIRMED)
        self.assertEqual(recovered, ["complete-flow-task:retry-complete-flow"])

        event_types = [event.event_type for event in events.snapshot()]
        expected_order = [
            LifecycleEventType.TASK_STARTED,
            LifecycleEventType.EVIDENCE_COLLECTED,
            LifecycleEventType.AGENT_REPORTED_COMPLETION,
            LifecycleEventType.VERIFICATION_RESULT,
            LifecycleEventType.RECOVERY_REQUESTED,
            LifecycleEventType.RECOVERY_BLOCKED,
            LifecycleEventType.RECOVERY_REQUESTED,
            LifecycleEventType.RECOVERY_CONFIRMED,
        ]
        cursor = 0
        for event_type in expected_order:
            cursor = event_types.index(event_type, cursor) + 1


if __name__ == "__main__":
    unittest.main()
