"""Export a deterministic Runmantle task to CortexOps-compatible local JSONL."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

from runmantle import (
    CapabilityDeclaration,
    FunctionWorker,
    InMemoryRuntime,
    PredicateCriterion,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    WorkerReport,
)
from runmantle.integrations.cortexops import (
    CortexOpsIntegrationConfig,
    create_cortexops_event_sink,
)


async def main() -> None:
    async def execute(
        task: TaskContract[int, int],
        context: TaskContext,
    ) -> WorkerReport[int]:
        context.evidence.record(
            "calculation",
            {"input": task.input, "output": task.input * 2},
            source="cortexops-export-example",
            evidence_id="calculation-evidence",
        )
        return WorkerReport.completed(task.input * 2)

    worker = FunctionWorker[int, int](
        id="doubling-worker",
        name="Doubling worker",
        role="example",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name="calculate",
                description="Perform an in-memory calculation.",
            ),
        ),
        handler=execute,
    )
    contract = TaskContract[int, int](
        task_id="cortexops-export-example",
        objective="Double 21.",
        input=21,
        acceptance_criteria=(
            PredicateCriterion(
                name="answer-is-42",
                description="The answer must be 42.",
                predicate=lambda output, evidence: output == 42,
            ),
        ),
        required_evidence=(),
        allowed_capabilities=frozenset({"calculate"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=1),
        idempotency_key="cortexops-export-example-key",
    )
    output_path = Path("./cortexops_runmantle_events.jsonl")
    sink = create_cortexops_event_sink(
        CortexOpsIntegrationConfig(enabled=True, export_path=output_path)
    )
    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(),
        event_sink=sink,
    ).execute(worker, contract, correlation_id="cortexops-export-session")
    print(f"status={result.status.value} events={output_path}")


if __name__ == "__main__":
    asyncio.run(main())
