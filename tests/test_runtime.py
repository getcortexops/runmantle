from __future__ import annotations

import asyncio
import unittest
from collections.abc import Awaitable, Callable
from datetime import timedelta

from runmantle import (
    CancellationToken,
    Capability,
    ContractVerifier,
    EvidenceRequirement,
    FunctionWorker,
    InMemoryEventSink,
    InMemoryRuntime,
    LifecycleEventType,
    PredicateCriterion,
    RiskLevel,
    TaskContext,
    TaskContract,
    TaskErrorCode,
    TaskStatus,
    WorkerReport,
    WorkerReportedStatus,
)


def contract(
    *,
    timeout: timedelta = timedelta(seconds=1),
    required_evidence: tuple[EvidenceRequirement, ...] = (),
) -> TaskContract[int, int]:
    return TaskContract(
        task_id="runtime-task",
        objective="Return the supplied integer.",
        input=7,
        acceptance_criteria=(
            PredicateCriterion(
                name="identity",
                description="Output must equal input.",
                predicate=lambda output, evidence: output == 7,
            ),
        ),
        required_evidence=required_evidence,
        allowed_capabilities=frozenset({"identity"}),
        risk_level=RiskLevel.LOW,
        timeout=timeout,
        idempotency_key="runtime-task-7",
        metadata={"suite": "runtime"},
    )


Handler = Callable[
    [TaskContract[int, int], TaskContext],
    Awaitable[WorkerReport[int]],
]


def worker(handler: Handler) -> FunctionWorker[int, int]:
    return FunctionWorker(
        id="identity-worker",
        name="Identity worker",
        role="test-fixture",
        version="1.0.0",
        capabilities=(Capability("identity", "Return an integer."),),
        handler=handler,
    )


class RuntimeTest(unittest.IsolatedAsyncioTestCase):
    async def test_worker_exception_fails_the_task(self) -> None:
        async def fail(
            task: TaskContract[int, int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            raise RuntimeError("deterministic failure")

        events = InMemoryEventSink()
        result = await InMemoryRuntime(
            verifier=ContractVerifier(),
            event_sink=events,
        ).execute(worker(fail), contract())

        self.assertEqual(result.status, TaskStatus.FAILED)
        self.assertIsNone(result.reported_status)
        self.assertEqual(result.errors[0].code, TaskErrorCode.WORKER_FAILURE)
        self.assertEqual(result.errors[0].error_type, "RuntimeError")
        self.assertEqual(
            self._transitions(events),
            [TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.FAILED],
        )
        self.assertIn(
            LifecycleEventType.TASK_FAILED,
            {event.event_type for event in events.snapshot()},
        )

    async def test_timeout_cancels_worker_and_fails_the_task(self) -> None:
        blocker = asyncio.Event()

        async def wait_forever(
            task: TaskContract[int, int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            await blocker.wait()
            return WorkerReport.completed(task.input)

        result = await InMemoryRuntime(verifier=ContractVerifier()).execute(
            worker(wait_forever),
            contract(timeout=timedelta(milliseconds=5)),
        )

        self.assertEqual(result.status, TaskStatus.FAILED)
        self.assertEqual(result.errors[0].code, TaskErrorCode.TIMEOUT)
        self.assertIsNone(result.final_verification_result)

    async def test_cancellation_stops_running_worker(self) -> None:
        started = asyncio.Event()
        cancellation = CancellationToken()

        async def wait_for_cancellation(
            task: TaskContract[int, int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            started.set()
            await asyncio.Event().wait()
            return WorkerReport.completed(task.input)

        execution = asyncio.create_task(
            InMemoryRuntime(verifier=ContractVerifier()).execute(
                worker(wait_for_cancellation),
                contract(),
                cancellation=cancellation,
            )
        )
        await started.wait()
        cancellation.cancel()
        result = await execution

        self.assertEqual(result.status, TaskStatus.FAILED)
        self.assertEqual(result.errors[0].code, TaskErrorCode.CANCELLED)

    async def test_worker_completion_is_not_verification(self) -> None:
        async def claim_complete(
            task: TaskContract[int, int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            return WorkerReport.completed(task.input)

        events = InMemoryEventSink()
        result = await InMemoryRuntime(event_sink=events).execute(
            worker(claim_complete),
            contract(),
        )

        self.assertEqual(result.reported_status, WorkerReportedStatus.COMPLETED)
        self.assertEqual(result.status, TaskStatus.AGENT_REPORTED_COMPLETE)
        self.assertFalse(result.succeeded)
        self.assertIsNone(result.final_verification_result)
        self.assertEqual(
            self._transitions(events),
            [
                TaskStatus.PENDING,
                TaskStatus.RUNNING,
                TaskStatus.AGENT_REPORTED_COMPLETE,
            ],
        )

    async def test_missing_required_evidence_waits_without_verification(self) -> None:
        async def no_evidence(
            task: TaskContract[int, int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            return WorkerReport.completed(task.input)

        result = await InMemoryRuntime(verifier=ContractVerifier()).execute(
            worker(no_evidence),
            contract(
                required_evidence=(
                    EvidenceRequirement("receipt", "A deterministic receipt."),
                )
            ),
        )

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertEqual(result.errors[0].code, TaskErrorCode.MISSING_EVIDENCE)
        self.assertEqual(
            result.final_verification_result.missing_evidence
            if result.final_verification_result
            else (),
            ("receipt",),
        )

    @staticmethod
    def _transitions(events: InMemoryEventSink) -> list[TaskStatus]:
        return [
            event.state
            for event in events.snapshot()
            if event.event_type is LifecycleEventType.STATE_TRANSITION
        ]


if __name__ == "__main__":
    unittest.main()
