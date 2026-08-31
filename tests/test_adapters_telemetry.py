from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from runmantle import (
    AgentAdapterContract,
    AgentAdapterWorker,
    AgentHealthStatus,
    AgentIdentity,
    CapabilityDeclaration,
    CortexOpsEventSink,
    EvidenceCollection,
    EvidenceItem,
    EvidenceRequirement,
    FakeAgentAdapter,
    FieldEqualsCriterion,
    FunctionWorker,
    InMemoryEventSink,
    InMemoryRuntime,
    JsonlEventSink,
    LangGraphAdapterBoundary,
    LifecycleEvent,
    LifecycleEventType,
    RiskLevel,
    RuleBasedVerifier,
    TaskContext,
    TaskContract,
    TaskStatus,
    WorkerReport,
)

COLLECTED_AT = datetime(2026, 8, 26, 9, 30, tzinfo=UTC)
Payload = dict[str, int]


def calculation_contract() -> TaskContract[Payload, Payload]:
    return TaskContract(
        task_id="calculate-task",
        objective="Double the supplied value.",
        input={"value": 21},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="output-is-42",
                description="The reported output must contain value 42.",
                field_path="value",
                expected=42,
            ),
            FieldEqualsCriterion(
                name="receipt-is-42",
                description="The evidence receipt must contain value 42.",
                field_path="value",
                expected=42,
                evidence_type="calculation_receipt",
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                "calculation_receipt",
                "A deterministic calculation receipt.",
            ),
        ),
        allowed_capabilities=frozenset({"calculate"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=1),
        idempotency_key="calculate-21",
    )


def calculation_capability() -> CapabilityDeclaration:
    return CapabilityDeclaration(
        name="calculate",
        description="Perform an in-memory deterministic calculation.",
    )


class ExistingFakeAgent:
    """Existing application object with no Runmantle-specific methods."""

    async def run(self, payload: Mapping[str, int]) -> Payload:
        return {"value": payload["value"] * 2}


class FakeTransport:
    def __init__(self) -> None:
        self.events: list[Mapping[str, Any]] = []

    def publish_event(self, event: Mapping[str, Any]) -> None:
        self.events.append(event)


class FakeLangGraphRunnable:
    async def ainvoke(
        self,
        input: Payload,
        config: Mapping[str, Any] | None = None,
    ) -> Payload:
        del config
        return {"value": input["value"] * 2}


class AdapterTelemetryTest(unittest.IsolatedAsyncioTestCase):
    async def test_existing_agent_and_native_worker_share_runtime_contract(
        self,
    ) -> None:
        existing_agent = ExistingFakeAgent()

        async def submit(
            task: TaskContract[Payload, Payload],
            context: TaskContext,
        ) -> WorkerReport[Payload]:
            context.event_emitter.emit("calculation.started", {"percent": 0})
            context.event_emitter.emit(
                "calculator.requested",
                {"action": "double"},
                event_type=LifecycleEventType.TOOL_ACTION_REQUESTED,
            )
            output = await existing_agent.run(task.input)
            context.evidence.record(
                "calculation_receipt",
                output,
                source="existing-fake-agent",
                evidence_id="adapter-receipt",
            )
            context.event_emitter.emit("calculation.completed", {"percent": 100})
            return WorkerReport.completed(output)

        adapter = FakeAgentAdapter[Payload, Payload](
            adapter_contract=AgentAdapterContract(
                identity=AgentIdentity(
                    agent_id="existing-agent",
                    name="Existing fake agent",
                    role="test-fixture",
                    version="1.0.0",
                ),
                capabilities=(calculation_capability(),),
                emits_evidence=True,
            ),
            submit_handler=submit,
        )
        adapter_events = InMemoryEventSink()
        adapter_result = await InMemoryRuntime(
            verifier=RuleBasedVerifier(),
            event_sink=adapter_events,
        ).execute(
            AgentAdapterWorker(adapter),
            calculation_contract(),
            correlation_id="adapter-correlation",
        )

        async def native_execute(
            task: TaskContract[Payload, Payload],
            context: TaskContext,
        ) -> WorkerReport[Payload]:
            output = {"value": task.input["value"] * 2}
            context.evidence.record(
                "calculation_receipt",
                output,
                source="native-worker",
                evidence_id="native-receipt",
            )
            return WorkerReport.completed(output)

        native_result = await InMemoryRuntime(
            verifier=RuleBasedVerifier(),
        ).execute(
            FunctionWorker[Payload, Payload](
                id="native-worker",
                name="Native worker",
                role="test-fixture",
                version="1.0.0",
                capabilities=(calculation_capability(),),
                handler=native_execute,
            ),
            calculation_contract(),
            correlation_id="native-correlation",
        )

        self.assertEqual(adapter_result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertEqual(native_result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertEqual(adapter_result.output, native_result.output)
        self.assertEqual((await adapter.health()).status, AgentHealthStatus.HEALTHY)
        event_types = {event.event_type for event in adapter_events.snapshot()}
        self.assertTrue(
            {
                LifecycleEventType.TASK_STARTED,
                LifecycleEventType.TASK_PROGRESS,
                LifecycleEventType.TOOL_ACTION_REQUESTED,
                LifecycleEventType.EVIDENCE_COLLECTED,
                LifecycleEventType.AGENT_REPORTED_COMPLETION,
                LifecycleEventType.VERIFICATION_RESULT,
            }.issubset(event_types)
        )

    async def test_langgraph_boundary_is_structural_and_dependency_free(self) -> None:
        boundary = LangGraphAdapterBoundary[Payload, Payload, Payload](
            adapter_contract=AgentAdapterContract(
                identity=AgentIdentity(
                    agent_id="langgraph-boundary",
                    name="Injected runnable",
                    role="optional-adapter",
                    version="0.1.0",
                ),
                capabilities=(calculation_capability(),),
                emits_evidence=True,
            ),
            runnable=FakeLangGraphRunnable(),
            output_mapper=lambda raw: raw,
            evidence_mapper=lambda raw: EvidenceCollection(
                (
                    EvidenceItem(
                        evidence_id="langgraph-receipt",
                        type="calculation_receipt",
                        payload=raw,
                        source="injected-runnable",
                        collected_at=COLLECTED_AT,
                    ),
                )
            ),
        )

        result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
            AgentAdapterWorker(boundary),
            calculation_contract(),
        )

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertEqual((await boundary.health()).status, AgentHealthStatus.UNKNOWN)


class TelemetrySinkTest(unittest.TestCase):
    def event(self) -> LifecycleEvent:
        return LifecycleEvent(
            event_type=LifecycleEventType.TASK_PROGRESS,
            task_id="telemetry-task",
            correlation_id="telemetry-correlation",
            worker_id="telemetry-worker",
            occurred_at=COLLECTED_AT,
            sequence=1,
            state=TaskStatus.RUNNING,
            name="halfway",
            details={"percent": 50, "risk": RiskLevel.LOW},
        )

    def test_jsonl_sink_writes_transport_safe_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            JsonlEventSink(path).emit(self.event())

            document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(document["event_type"], "task.progress")
        self.assertEqual(document["details"], {"percent": 50, "risk": "low"})

    def test_cortexops_sink_uses_only_injected_transport(self) -> None:
        transport = FakeTransport()
        sink = CortexOpsEventSink(
            transport=transport,
            capabilities=(
                CapabilityDeclaration(
                    name="emit_telemetry",
                    description="Publish serialized lifecycle events.",
                ),
            ),
        )

        sink.emit(self.event())

        self.assertEqual(len(transport.events), 1)
        self.assertEqual(transport.events[0]["task_id"], "telemetry-task")


if __name__ == "__main__":
    unittest.main()
