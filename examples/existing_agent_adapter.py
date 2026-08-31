"""Adapt an existing agent object without rewriting its implementation."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import timedelta

from runmantle import (
    AdapterRecoveryHooks,
    AgentAdapterContract,
    AgentAdapterWorker,
    AgentHealth,
    AgentHealthStatus,
    AgentIdentity,
    CapabilityDeclaration,
    EvidenceRequirement,
    FieldEqualsCriterion,
    InMemoryRuntime,
    LifecycleEventType,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    WorkerReport,
)

Payload = dict[str, int]


class ExistingCalculatorAgent:
    """Application object that knows nothing about Runmantle."""

    async def invoke(self, values: Mapping[str, int]) -> Payload:
        return {"total": values["left"] + values["right"]}


class CalculatorAgentAdapter:
    """Translate the existing object's interface into the AgentAdapter protocol."""

    def __init__(self, agent: ExistingCalculatorAgent) -> None:
        self._agent = agent
        self.adapter_contract = AgentAdapterContract(
            identity=AgentIdentity(
                agent_id="existing-calculator",
                name="Existing calculator agent",
                role="arithmetic",
                version="1.0.0",
            ),
            capabilities=(
                CapabilityDeclaration(
                    name="addition",
                    description="Add two integers in memory.",
                ),
            ),
            emits_evidence=True,
        )
        self.recovery_hooks: AdapterRecoveryHooks | None = None

    async def submit(
        self,
        task: TaskContract[Payload, Payload],
        context: TaskContext,
    ) -> WorkerReport[Payload]:
        context.require_capability("addition")
        context.event_emitter.emit(
            "existing_agent.invoke",
            {"action": "addition"},
            event_type=LifecycleEventType.TOOL_ACTION_REQUESTED,
        )
        output = await self._agent.invoke(task.input)
        context.evidence.record(
            "calculation",
            output,
            source="existing-calculator-adapter",
            evidence_id="existing-agent-calculation",
        )
        return WorkerReport.completed(output)

    async def health(self) -> AgentHealth:
        return AgentHealth(AgentHealthStatus.HEALTHY, "local object is available")


contract = TaskContract[Payload, Payload](
    task_id="existing-agent-demo",
    objective="Add 19 and 23 through an existing agent object.",
    input={"left": 19, "right": 23},
    acceptance_criteria=(
        FieldEqualsCriterion(
            name="correct-total",
            description="The output total must equal 42.",
            field_path="total",
            expected=42,
        ),
        FieldEqualsCriterion(
            name="evidenced-total",
            description="The evidence total must equal 42.",
            field_path="total",
            expected=42,
            evidence_type="calculation",
        ),
    ),
    required_evidence=(
        EvidenceRequirement("calculation", "The adapter-observed result."),
    ),
    allowed_capabilities=frozenset({"addition"}),
    risk_level=RiskLevel.LOW,
    timeout=timedelta(seconds=1),
    idempotency_key="existing-agent-19-23",
)


async def main() -> None:
    adapter = CalculatorAgentAdapter(ExistingCalculatorAgent())
    worker = AgentAdapterWorker[Payload, Payload](adapter)
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        worker,
        contract,
        correlation_id="existing-agent-example",
    )
    print(f"status={result.status.value} output={result.output}")


if __name__ == "__main__":
    asyncio.run(main())
