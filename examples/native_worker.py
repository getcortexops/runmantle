"""A native Runmantle worker with a typed contract and required evidence."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from runmantle import (
    CapabilityDeclaration,
    EvidenceRequirement,
    FunctionWorker,
    InMemoryRuntime,
    PredicateCriterion,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    WorkerReport,
)


async def uppercase(
    task: TaskContract[str, str],
    context: TaskContext,
) -> WorkerReport[str]:
    context.require_capability("uppercase")
    output = task.input.upper()
    context.evidence.record(
        "transformation",
        {"input": task.input, "output": output},
        source="native-uppercase-worker",
        evidence_id="uppercase-transformation",
    )
    return WorkerReport.completed(output)


worker = FunctionWorker[str, str](
    id="native-uppercase",
    name="Native uppercase worker",
    role="text-transformation",
    version="1.0.0",
    capabilities=(
        CapabilityDeclaration(
            name="uppercase",
            description="Uppercase text in memory.",
        ),
    ),
    handler=uppercase,
)

contract = TaskContract[str, str](
    task_id="native-uppercase-demo",
    objective="Uppercase 'runmantle' and record the transformation.",
    input="runmantle",
    acceptance_criteria=(
        PredicateCriterion(
            name="uppercase-output",
            description="The output must be RUNMANTLE.",
            predicate=lambda output, evidence: output == "RUNMANTLE",
        ),
    ),
    required_evidence=(
        EvidenceRequirement(
            evidence_type="transformation",
            description="The input and transformed output.",
        ),
    ),
    allowed_capabilities=frozenset({"uppercase"}),
    risk_level=RiskLevel.LOW,
    timeout=timedelta(seconds=1),
    idempotency_key="native-uppercase-runmantle",
)


async def main() -> None:
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        worker,
        contract,
        correlation_id="native-worker-example",
    )
    print(f"status={result.status.value} output={result.output!r}")


if __name__ == "__main__":
    asyncio.run(main())
