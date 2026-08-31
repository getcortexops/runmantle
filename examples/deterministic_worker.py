"""Deterministic async worker with evidence and explicit verification."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from runmantle import (
    CapabilityDeclaration,
    EvidenceRequirement,
    FunctionWorker,
    InMemoryEventSink,
    InMemoryRuntime,
    PredicateCriterion,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    WorkerReport,
)


async def add(
    task: TaskContract[tuple[int, int], int],
    context: TaskContext,
) -> WorkerReport[int]:
    context.require_capability("integer-addition")
    left, right = task.input
    output = left + right
    context.evidence.record(
        "calculation",
        {"operation": "addition", "left": left, "right": right, "output": output},
        source="deterministic-adder",
        provenance={"worker_version": "1.0.0", "method": "integer-addition"},
        artifact_reference="memory://demo-addition/calculation",
    )
    return WorkerReport.completed(output)


worker = FunctionWorker[tuple[int, int], int](
    id="deterministic-adder",
    name="Deterministic adder",
    role="arithmetic",
    version="1.0.0",
    capabilities=(
        CapabilityDeclaration(
            "integer-addition",
            "Add exactly two integers.",
        ),
    ),
    handler=add,
)

contract = TaskContract[tuple[int, int], int](
    task_id="demo-addition",
    objective="Add 20 and 22 with calculation evidence.",
    input=(20, 22),
    acceptance_criteria=(
        PredicateCriterion(
            name="correct-total",
            description="The output must equal 42.",
            predicate=lambda output, evidence: output == 42,
        ),
    ),
    required_evidence=(
        EvidenceRequirement(
            "calculation",
            "Operands and computed output.",
            consistent_fields=("output",),
        ),
    ),
    allowed_capabilities=frozenset({"integer-addition"}),
    risk_level=RiskLevel.LOW,
    timeout=timedelta(seconds=1),
    idempotency_key="demo-addition-20-22",
)


async def main() -> None:
    events = InMemoryEventSink()
    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(),
        event_sink=events,
    ).execute(worker, contract)
    print(f"status={result.status} output={result.output}")
    print(f"evidence={len(result.evidence)} events={len(events.snapshot())}")


if __name__ == "__main__":
    asyncio.run(main())
