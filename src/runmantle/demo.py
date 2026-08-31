"""Deterministic demo showing that worker evidence remains an unverified claim."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .adapters import FunctionWorker
from .capabilities import CapabilityDeclaration
from .contracts import RiskLevel, TaskContract
from .core import TaskContext, TaskResult, WorkerReport
from .evidence import EvidenceRequirement
from .runtime import InMemoryRuntime
from .telemetry import InMemoryEventSink, LifecycleEvent
from .verification import FieldEqualsCriterion, PredicateCriterion, RuleBasedVerifier


@dataclass(frozen=True, slots=True)
class DemoRun:
    """Result and emitted events from one deterministic demo execution."""

    result: TaskResult[int]
    events: tuple[LifecycleEvent, ...]


async def _add(
    task: TaskContract[tuple[int, int], int],
    context: TaskContext,
) -> WorkerReport[int]:
    context.require_capability("integer-addition")
    left, right = task.input
    output = left + right
    context.event_emitter.emit("addition.calculated", {"output": output})
    context.evidence.record(
        "calculation",
        {"left": left, "right": right, "output": output},
        source="runmantle-demo",
        provenance={"method": "integer-addition", "worker_version": "1.0.0"},
        evidence_id="demo-calculation",
    )
    return WorkerReport.completed(output)


def create_deterministic_demo() -> tuple[
    FunctionWorker[tuple[int, int], int],
    TaskContract[tuple[int, int], int],
]:
    """Create the native worker and contract used by the packaged demo."""

    worker = FunctionWorker[tuple[int, int], int](
        id="deterministic-adder",
        name="Deterministic adder",
        role="developer-preview-demo",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name="integer-addition",
                description="Add exactly two integers in memory.",
            ),
        ),
        handler=_add,
    )
    contract = TaskContract[tuple[int, int], int](
        task_id="demo-addition",
        objective="Add 20 and 22 and report worker-owned calculation evidence.",
        input=(20, 22),
        acceptance_criteria=(
            PredicateCriterion(
                name="correct-output",
                description="The output must equal 42.",
                predicate=lambda output, evidence: output == 42,
            ),
            FieldEqualsCriterion(
                name="evidenced-output",
                description="The calculation evidence must contain output 42.",
                field_path="output",
                expected=42,
                evidence_type="calculation",
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type="calculation",
                description="The operands and calculated output.",
            ),
        ),
        allowed_capabilities=frozenset({"integer-addition"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=1),
        idempotency_key="demo-addition-20-22",
    )
    return worker, contract


async def run_deterministic_demo() -> DemoRun:
    """Execute the demo; its worker-owned evidence remains awaiting verification."""

    worker, contract = create_deterministic_demo()
    events = InMemoryEventSink()
    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(),
        event_sink=events,
    ).execute(
        worker,
        contract,
        correlation_id="runmantle-cli-demo",
    )
    return DemoRun(result=result, events=events.snapshot())
