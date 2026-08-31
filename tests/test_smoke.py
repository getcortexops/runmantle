from __future__ import annotations

import unittest
from datetime import timedelta

from runmantle import (
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
    TaskStatus,
    WorkerReport,
)


class SmokeTest(unittest.IsolatedAsyncioTestCase):
    async def test_worker_calculation_claim_is_not_verified_evidence(self) -> None:
        async def add(
            task: TaskContract[tuple[int, int], int],
            context: TaskContext,
        ) -> WorkerReport[int]:
            context.require_capability("integer-addition")
            left, right = task.input
            output = left + right
            context.evidence.record(
                "calculation",
                {"left": left, "right": right, "output": output},
                source="adder-v1",
            )
            context.event_emitter.emit("calculation.completed", {"output": output})
            return WorkerReport.completed(output)

        worker = FunctionWorker[tuple[int, int], int](
            id="worker-adder",
            name="Deterministic adder",
            role="arithmetic",
            version="1.0.0",
            capabilities=(Capability("integer-addition", "Add exactly two integers."),),
            handler=add,
        )
        contract = TaskContract[tuple[int, int], int](
            task_id="task-add",
            objective="Add two integers and demonstrate the result.",
            input=(20, 22),
            acceptance_criteria=(
                PredicateCriterion(
                    name="correct-total",
                    description="Output must be 42.",
                    predicate=lambda output, evidence: output == 42,
                ),
            ),
            required_evidence=(
                EvidenceRequirement(
                    "calculation", "The arithmetic operands and result."
                ),
            ),
            allowed_capabilities=frozenset({"integer-addition"}),
            risk_level=RiskLevel.LOW,
            timeout=timedelta(seconds=1),
            idempotency_key="addition-20-22",
        )
        events = InMemoryEventSink()

        result = await InMemoryRuntime(
            verifier=ContractVerifier(),
            event_sink=events,
            id_factory=lambda: "correlation-smoke",
        ).execute(worker, contract)

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertFalse(result.succeeded)
        self.assertEqual(result.output, 42)
        self.assertEqual(len(result.evidence), 1)
        self.assertFalse(
            result.final_verification_result.passed
            if result.final_verification_result
            else False
        )
        transitions = [
            event.state
            for event in events.snapshot()
            if event.event_type is LifecycleEventType.STATE_TRANSITION
        ]
        self.assertEqual(
            transitions,
            [
                TaskStatus.PENDING,
                TaskStatus.RUNNING,
                TaskStatus.AGENT_REPORTED_COMPLETE,
                TaskStatus.VERIFYING,
                TaskStatus.AWAITING_EVIDENCE,
            ],
        )


if __name__ == "__main__":
    unittest.main()
