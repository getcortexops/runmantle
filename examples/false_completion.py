"""Agent-reported completion that deterministic verification rejects."""

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


async def incorrect_answer(
    task: TaskContract[None, int],
    context: TaskContext,
) -> WorkerReport[int]:
    del task
    context.evidence.record(
        "calculation",
        {"output": 41},
        source="incorrect-worker",
        evidence_id="incorrect-calculation",
    )
    return WorkerReport.completed(41)


worker = FunctionWorker[None, int](
    id="incorrect-worker",
    name="Incorrect completion worker",
    role="failure-demonstration",
    version="1.0.0",
    capabilities=(
        CapabilityDeclaration(
            name="calculate",
            description="Return a deterministic demonstration value.",
        ),
    ),
    handler=incorrect_answer,
)

contract = TaskContract[None, int](
    task_id="false-completion-demo",
    objective="Return exactly 42.",
    input=None,
    acceptance_criteria=(
        PredicateCriterion(
            name="answer-is-42",
            description="The reported answer must equal 42.",
            predicate=lambda output, evidence: output == 42,
        ),
    ),
    required_evidence=(EvidenceRequirement("calculation", "The calculation output."),),
    allowed_capabilities=frozenset({"calculate"}),
    risk_level=RiskLevel.LOW,
    timeout=timedelta(seconds=1),
    idempotency_key="false-completion-42",
)


async def main() -> None:
    events = InMemoryEventSink()
    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(),
        event_sink=events,
    ).execute(worker, contract, correlation_id="false-completion-example")
    states = [
        event.state.value
        for event in events.snapshot()
        if event.event_type.value == "task.state_transition"
    ]
    print(f"reported={result.reported_status} final={result.status.value}")
    print(" -> ".join(states))


if __name__ == "__main__":
    asyncio.run(main())
