from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from runmantle import (
    CapabilityRegistry,
    InMemoryEventSink,
    InMemoryRecoveryExecutor,
    LifecycleEventType,
    PredicateCriterion,
    RecoveryAction,
    RecoveryApproval,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryReasonCode,
    RecoveryStatus,
    RiskLevel,
    RuntimeConfirmation,
    StandardCapability,
    TaskContract,
    TaskStatus,
)

CONFIRMED_AT = datetime(2026, 2, 3, 4, 5, tzinfo=UTC)


def task_contract(
    *,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> TaskContract[int, int]:
    return TaskContract(
        task_id="recoverable-task",
        objective="Return seven.",
        input=7,
        acceptance_criteria=(
            PredicateCriterion(
                name="is-seven",
                description="Output must equal seven.",
                predicate=lambda output, evidence: output == 7,
            ),
        ),
        required_evidence=(),
        allowed_capabilities=frozenset({StandardCapability.RETRY}),
        risk_level=risk_level,
        timeout=timedelta(seconds=1),
        idempotency_key="recoverable-task-key",
    )


def recovery_action(
    *,
    capability: str = StandardCapability.RETRY,
    action_id: str = "retry-action",
) -> RecoveryAction:
    return RecoveryAction(
        action_id=action_id,
        capability=capability,
        idempotency_key="recoverable-task-key",
        reason="Retry after a deterministic transient failure.",
        parameters={"attempt": 2},
    )


def recovery_plan(action: RecoveryAction) -> RecoveryPlan:
    return RecoveryPlan(
        plan_id="recovery-plan",
        task_id="recoverable-task",
        actions=(action,),
        proposed_by="worker-agent-report",
    )


def confirmation(action: RecoveryAction) -> RuntimeConfirmation:
    return RuntimeConfirmation(
        confirmation_id="confirmation-1",
        action_id=action.action_id,
        capability=action.capability,
        idempotency_key=action.idempotency_key,
        supported=True,
        safe=True,
        confirmed_at=CONFIRMED_AT,
        confirmed_by="local-runtime",
        reason="Retry handler is installed and the task operation is idempotent.",
    )


def approval(action: RecoveryAction) -> RecoveryApproval:
    return RecoveryApproval(
        action_id=action.action_id,
        capability=action.capability,
        idempotency_key=action.idempotency_key,
        approved=True,
        approved_by="test-policy-owner",
        reason="Recovery was reviewed and approved.",
    )


def policy(
    *,
    require_approval: bool = False,
    maximum_risk: RiskLevel = RiskLevel.MEDIUM,
) -> RecoveryPolicy:
    return RecoveryPolicy(
        allowed_capabilities=frozenset({StandardCapability.RETRY}),
        allowed_task_states=frozenset({TaskStatus.FAILED}),
        maximum_risk_level=maximum_risk,
        approval_required_capabilities=(
            frozenset({StandardCapability.RETRY}) if require_approval else frozenset()
        ),
        require_runtime_confirmation=True,
    )


class RecoveryExecutorTest(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_recovery_capability_is_blocked(self) -> None:
        action = recovery_action(capability="deploy")
        events = InMemoryEventSink()
        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=RecoveryPolicy(
                allowed_capabilities=frozenset({"deploy"}),
                maximum_risk_level=RiskLevel.LOW,
            ),
            event_sink=events,
        )

        result = await executor.execute(
            recovery_plan(action),
            contract=task_contract(),
            task_state=TaskStatus.FAILED,
        )

        self.assertEqual(result.status, RecoveryStatus.BLOCKED)
        self.assertEqual(
            result.actions[0].reason.code,
            RecoveryReasonCode.UNSUPPORTED_CAPABILITY,
        )
        self.assertEqual(
            [event.event_type for event in events.snapshot()],
            [
                LifecycleEventType.RECOVERY_REQUESTED,
                LifecycleEventType.RECOVERY_BLOCKED,
            ],
        )

    async def test_unsafe_retry_is_blocked_by_risk(self) -> None:
        action = recovery_action()
        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(maximum_risk=RiskLevel.HIGH),
        )

        result = await executor.execute(
            recovery_plan(action),
            contract=task_contract(risk_level=RiskLevel.HIGH),
            task_state=TaskStatus.FAILED,
            confirmations=(confirmation(action),),
        )

        self.assertEqual(result.status, RecoveryStatus.BLOCKED)
        self.assertEqual(
            result.actions[0].reason.code,
            RecoveryReasonCode.RISK_EXCEEDS_CAPABILITY,
        )

    async def test_missing_runtime_confirmation_prevents_recovery(self) -> None:
        action = recovery_action()
        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(),
        )

        result = await executor.execute(
            recovery_plan(action),
            contract=task_contract(),
            task_state=TaskStatus.FAILED,
        )

        self.assertEqual(
            result.status,
            RecoveryStatus.AWAITING_RUNTIME_CONFIRMATION,
        )
        self.assertEqual(
            result.actions[0].reason.code,
            RecoveryReasonCode.RUNTIME_CONFIRMATION_REQUIRED,
        )

    async def test_recovery_reports_approval_required(self) -> None:
        action = recovery_action()
        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(require_approval=True),
        )

        result = await executor.execute(
            recovery_plan(action),
            contract=task_contract(),
            task_state=TaskStatus.FAILED,
            confirmations=(confirmation(action),),
        )

        self.assertEqual(result.status, RecoveryStatus.APPROVAL_REQUIRED)

    async def test_approved_and_confirmed_recovery_executes_handler(self) -> None:
        action = recovery_action()
        executed: list[str] = []
        events = InMemoryEventSink()

        async def retry_handler(
            recovery: RecoveryAction,
            contract: TaskContract[Any, Any],
        ) -> None:
            executed.append(f"{contract.task_id}:{recovery.action_id}")

        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(require_approval=True),
            handlers={StandardCapability.RETRY: retry_handler},
            event_sink=events,
        )

        result = await executor.execute(
            recovery_plan(action),
            contract=task_contract(),
            task_state=TaskStatus.FAILED,
            confirmations=(confirmation(action),),
            approvals=(approval(action),),
        )

        self.assertEqual(result.status, RecoveryStatus.RUNTIME_CONFIRMED)
        self.assertTrue(result.executed)
        self.assertEqual(executed, ["recoverable-task:retry-action"])
        self.assertEqual(
            [event.event_type for event in events.snapshot()],
            [
                LifecycleEventType.RECOVERY_REQUESTED,
                LifecycleEventType.RUNTIME_CONFIRMATION_RECEIVED,
                LifecycleEventType.RECOVERY_CONFIRMED,
            ],
        )

    async def test_duplicate_recovery_is_prevented_by_idempotency_key(self) -> None:
        action = recovery_action()
        calls = 0

        async def retry_handler(
            recovery: RecoveryAction,
            contract: TaskContract[Any, Any],
        ) -> None:
            nonlocal calls
            calls += 1

        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(),
            handlers={StandardCapability.RETRY: retry_handler},
        )
        contract = task_contract()
        confirmations = (confirmation(action),)

        first = await executor.execute(
            recovery_plan(action),
            contract=contract,
            task_state=TaskStatus.FAILED,
            confirmations=confirmations,
        )
        second = await executor.execute(
            recovery_plan(action),
            contract=contract,
            task_state=TaskStatus.FAILED,
            confirmations=confirmations,
        )

        self.assertEqual(first.status, RecoveryStatus.RUNTIME_CONFIRMED)
        self.assertEqual(second.status, RecoveryStatus.DUPLICATE_PREVENTED)
        self.assertEqual(
            second.actions[0].reason.code,
            RecoveryReasonCode.DUPLICATE_IDEMPOTENCY_KEY,
        )
        self.assertEqual(calls, 1)

    async def test_dry_run_does_not_execute_or_consume_idempotency_key(self) -> None:
        action = recovery_action()
        calls = 0

        async def retry_handler(
            recovery: RecoveryAction,
            contract: TaskContract[Any, Any],
        ) -> None:
            nonlocal calls
            calls += 1

        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(),
            handlers={StandardCapability.RETRY: retry_handler},
        )
        contract = task_contract()
        confirmations = (confirmation(action),)

        dry_run = await executor.execute(
            recovery_plan(action),
            contract=contract,
            task_state=TaskStatus.FAILED,
            confirmations=confirmations,
            dry_run=True,
        )
        executed = await executor.execute(
            recovery_plan(action),
            contract=contract,
            task_state=TaskStatus.FAILED,
            confirmations=confirmations,
        )

        self.assertEqual(dry_run.status, RecoveryStatus.DRY_RUN)
        self.assertEqual(executed.status, RecoveryStatus.RUNTIME_CONFIRMED)
        self.assertEqual(calls, 1)

    async def test_handler_failure_returns_structured_reason(self) -> None:
        action = recovery_action()

        async def failing_handler(
            recovery: RecoveryAction,
            contract: TaskContract[Any, Any],
        ) -> None:
            raise RuntimeError("simulated recovery failure")

        executor = InMemoryRecoveryExecutor(
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=policy(),
            handlers={StandardCapability.RETRY: failing_handler},
        )

        result = await executor.execute(
            recovery_plan(action),
            contract=task_contract(),
            task_state=TaskStatus.FAILED,
            confirmations=(confirmation(action),),
        )

        self.assertEqual(result.status, RecoveryStatus.FAILED)
        self.assertEqual(
            result.actions[0].reason.code,
            RecoveryReasonCode.EXECUTION_FAILED,
        )
        self.assertEqual(result.actions[0].error_type, "RuntimeError")


if __name__ == "__main__":
    unittest.main()
