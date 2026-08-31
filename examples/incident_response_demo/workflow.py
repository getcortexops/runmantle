"""Consumer-owned incident workflow built on Runmantle's public boundaries."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict

from runmantle import (
    ApprovalDecision,
    ApproverIdentity,
    CapabilityDeclaration,
    CapabilityRegistry,
    DurableRecoveryExecutor,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    InMemoryEvidenceCollector,
    InMemoryRuntime,
    LifecycleEvent,
    LifecycleEventType,
    PreActionCapabilityConfirmation,
    PredicateCriterion,
    RecoveryAction,
    RecoveryHandlerRegistration,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryPostcondition,
    RecoveryPrecondition,
    RecoveryResult,
    RiskLevel,
    RuleBasedVerifier,
    SQLiteStore,
    StandardCapability,
    TaskContext,
    TaskContract,
    TaskResult,
    TaskStatus,
    WorkerReport,
)
from runmantle.evidence import _establish_evidence_origin
from runmantle.integrations.cortexops import (
    CortexOpsEventSink,
    CortexOpsIntegrationConfig,
    CortexOpsJsonlExporter,
)

DEFAULT_EVENT_PATH = Path("./incident_response_events.jsonl")


@dataclass(frozen=True, slots=True)
class Incident:
    """The application-level incident received by the demo."""

    incident_id: str = "incident-api-001"
    service: str = "checkout-api"
    symptom: str = "health endpoint reports unhealthy"


@dataclass(frozen=True, slots=True)
class TriageFinding:
    classification: str
    affected_service: str


@dataclass(frozen=True, slots=True)
class Diagnosis:
    root_cause: str
    worker_claim: str


class HealthSignal(TypedDict):
    service: str
    healthy: bool
    check_number: int
    source: str


@dataclass(slots=True)
class DeterministicClock:
    """A predictable clock shared by runtime, evidence, and confirmations."""

    next_value: datetime = datetime(2026, 8, 26, 9, 0, tzinfo=UTC)
    step: timedelta = timedelta(seconds=1)

    def __call__(self) -> datetime:
        current = self.next_value
        self.next_value += self.step
        return current


@dataclass(slots=True)
class DeterministicIds:
    prefix: str
    next_value: int = 1

    def __call__(self) -> str:
        value = f"{self.prefix}-{self.next_value}"
        self.next_value += 1
        return value


@dataclass(slots=True)
class FakeIncidentRuntime:
    """Application-owned runtime whose only mutation is in-memory demo state."""

    clock: Callable[[], datetime]
    healthy: bool = False
    health_checks: int = 0
    simulated_recovery_executions: int = 0

    def inspect_health(self) -> HealthSignal:
        self.health_checks += 1
        return {
            "service": "checkout-api",
            "healthy": self.healthy,
            "check_number": self.health_checks,
            "source": "fake-runtime",
        }

    def confirm(self, action: RecoveryAction) -> PreActionCapabilityConfirmation:
        return PreActionCapabilityConfirmation(
            confirmation_id="fake-runtime-confirmation-001",
            action_id=action.action_id,
            capability=action.capability,
            idempotency_key=action.idempotency_key,
            supported=True,
            safe=True,
            confirmed_at=self.clock(),
            confirmed_by="fake-incident-runtime",
            reason="The simulation-only retry handler is installed and safe.",
            target_hash=action.action_hash,
        )

    def execute_simulated_recovery(self, action: RecoveryAction) -> None:
        if action.parameters.get("mode") != "simulation":
            raise PermissionError("the demo accepts simulation-mode recovery only")
        self.simulated_recovery_executions += 1
        self.healthy = True


@dataclass(slots=True)
class FakeHealthEvidenceProvider:
    """Observe the simulated service separately from the recovery handler."""

    runtime: FakeIncidentRuntime = field(compare=False, repr=False)

    async def acquire(
        self,
        plan: RecoveryPlan,
        action: RecoveryAction,
        receipt: Any,
    ) -> EvidenceItem:
        del action, receipt
        health = self.runtime.inspect_health()
        return EvidenceItem(
            evidence_id=f"{plan.plan_id}-postcondition-health",
            type="health_signal",
            source="fake-incident-health-provider",
            collected_at=self.runtime.clock(),
            payload=health,
            provenance={
                "recovery_plan_id": plan.plan_id,
                "acquired_after_executor_receipt": True,
            },
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        )


@dataclass(frozen=True, slots=True)
class IncidentResponseDemoResult:
    incident: Incident
    triage: TaskResult[TriageFinding]
    initial_diagnosis: TaskResult[Diagnosis]
    blocked_recovery: RecoveryResult
    confirmed_recovery: RecoveryResult
    recovery_executions_after_block: int
    simulated_recovery_executions: int
    final_diagnosis: TaskResult[Diagnosis]
    runtime_confirmation: PreActionCapabilityConfirmation
    approval: ApprovalDecision
    event_path: Path
    exported_events: tuple[dict[str, Any], ...] = field(repr=False)


def _triage_worker() -> FunctionWorker[Incident, TriageFinding]:
    async def investigate(
        task: TaskContract[Incident, TriageFinding],
        context: TaskContext,
    ) -> WorkerReport[TriageFinding]:
        context.require_capability("investigate_incident")
        context.event_emitter.emit("triage.investigating")
        finding = TriageFinding(
            classification="availability",
            affected_service=task.input.service,
        )
        context.evidence.record(
            "triage_finding",
            {
                "classification": finding.classification,
                "affected_service": finding.affected_service,
            },
            source="triage-worker",
            evidence_id="triage-finding-001",
        )
        return WorkerReport.completed(finding)

    return FunctionWorker(
        id="triage-worker",
        name="Incident triage worker",
        role="triage",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name="investigate_incident",
                description="Inspect deterministic incident input in memory.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=investigate,
    )


def _triage_contract(incident: Incident) -> TaskContract[Incident, TriageFinding]:
    return TaskContract(
        task_id=f"{incident.incident_id}-triage",
        objective="Classify the incident without performing external actions.",
        input=incident,
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="availability-classification",
                description="The incident must be classified as availability.",
                field_path="classification",
                expected="availability",
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                "triage_finding",
                "Structured evidence supporting the incident classification.",
            ),
        ),
        allowed_capabilities=frozenset({"investigate_incident"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{incident.incident_id}-triage-v1",
    )


def _diagnosis_worker(
    fake_runtime: FakeIncidentRuntime,
) -> FunctionWorker[Incident, Diagnosis]:
    async def diagnose(
        task: TaskContract[Incident, Diagnosis],
        context: TaskContext,
    ) -> WorkerReport[Diagnosis]:
        context.require_capability(StandardCapability.INSPECT_HEALTH)
        context.event_emitter.emit("diagnosis.investigating")
        health = fake_runtime.inspect_health()
        check_number = int(health["check_number"])
        context.evidence.record(
            "diagnostic_evidence",
            {
                "root_cause": "stale in-memory service state",
                "affected_service": task.input.service,
            },
            source="diagnosis-worker",
            evidence_id=f"diagnostic-evidence-{check_number}",
        )
        context.evidence.record(
            "health_signal",
            health,
            source="fake-incident-runtime",
            evidence_id=f"health-signal-{check_number}",
        )
        context.event_emitter.emit("health.check.completed")
        return WorkerReport.completed(
            Diagnosis(
                root_cause="stale in-memory service state",
                worker_claim="investigation complete",
            )
        )

    return FunctionWorker(
        id="diagnosis-worker",
        name="Incident diagnosis worker",
        role="diagnosis",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name=StandardCapability.INSPECT_HEALTH,
                description="Read health from the injected fake runtime.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=diagnose,
    )


def _diagnosis_contract(incident: Incident) -> TaskContract[Incident, Diagnosis]:
    return TaskContract(
        task_id=f"{incident.incident_id}-diagnosis",
        objective="Diagnose the incident and prove that service health is restored.",
        input=incident,
        acceptance_criteria=(
            PredicateCriterion(
                name="runtime-health-restored",
                description=(
                    "At least one independently observed health signal is healthy."
                ),
                predicate=lambda output, evidence: any(
                    item.payload is not None and item.payload.get("healthy") is True
                    for item in evidence.of_type("health_signal")
                ),
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                "health_signal",
                "A health signal independently read from the fake runtime.",
            ),
        ),
        allowed_capabilities=frozenset(
            {StandardCapability.INSPECT_HEALTH, StandardCapability.RETRY}
        ),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{incident.incident_id}-recovery-v1",
    )


def _read_exported_events(path: Path) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise TypeError("CortexOps JSONL row must be an object")
        rows.append(value)
    return tuple(rows)


async def run_incident_response_demo(
    event_path: str | Path = DEFAULT_EVENT_PATH,
) -> IncidentResponseDemoResult:
    """Run a real SQLite pause/decision/restart recovery workflow."""

    output_path = Path(event_path)
    database_path = output_path.with_suffix(".db")
    if output_path.exists():
        output_path.unlink()
    if database_path.exists():
        database_path.unlink()

    clock = DeterministicClock()
    evidence_ids = DeterministicIds("demo-evidence")
    sink = CortexOpsEventSink(
        exporter=CortexOpsJsonlExporter(output_path),
        config=CortexOpsIntegrationConfig(
            enabled=True,
            project="runmantle-incident-response-demo",
            environment="local-simulation",
            service_name="incident-response-demo",
            export_path=output_path,
        ),
    )
    fake_runtime = FakeIncidentRuntime(clock=clock)
    incident = Incident()
    correlation_id = f"{incident.incident_id}-session"

    sink.emit(
        LifecycleEvent(
            event_type=LifecycleEventType.WORKER_EVENT,
            task_id=f"{incident.incident_id}-triage",
            correlation_id=correlation_id,
            worker_id="incident-coordinator",
            occurred_at=clock(),
            sequence=1,
            state=TaskStatus.PENDING,
            name="incident.received",
            details={"service": incident.service},
        )
    )

    def triage_runtime() -> InMemoryRuntime:
        return InMemoryRuntime(
            verifier=RuleBasedVerifier(),
            evidence_factory=lambda: InMemoryEvidenceCollector(
                clock=clock,
                id_factory=evidence_ids,
            ),
            event_sink=sink,
            clock=clock,
            id_factory=DeterministicIds("correlation"),
        )

    triage = await triage_runtime().execute(
        _triage_worker(),
        _triage_contract(incident),
        correlation_id=correlation_id,
    )
    diagnosis_contract = _diagnosis_contract(incident)
    diagnosis_worker = _diagnosis_worker(fake_runtime)
    diagnosis_runtime = DurableRuntime(
        database_path=database_path,
        verifier=RuleBasedVerifier(clock=clock),
        event_sink=sink,
        clock=clock,
        id_factory=DeterministicIds("durable-correlation"),
    )
    initial_diagnosis = await diagnosis_runtime.execute(
        diagnosis_worker,
        diagnosis_contract,
        correlation_id=correlation_id,
    )
    diagnosis_runtime.store.record_evidence(
        diagnosis_contract.task_id,
        _establish_evidence_origin(
            EvidenceItem(
                evidence_id="runtime-initial-health",
                type="health_signal",
                source="fake-incident-runtime-boundary",
                collected_at=clock(),
                payload=fake_runtime.inspect_health(),
            ),
            boundary="incident_demo_runtime",
            provider_identity="runmantle.demo.initial_health:v1",
            provider_configuration={"mode": "simulation"},
            trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
            acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
        ),
    )
    initial_diagnosis = await diagnosis_runtime.resume(
        diagnosis_contract.task_id,
        contract=diagnosis_contract,
    )

    action = RecoveryAction(
        action_id="simulate-service-retry",
        capability=StandardCapability.RETRY,
        idempotency_key=diagnosis_contract.idempotency_key,
        reason="Retry only after failed health verification.",
        parameters={"mode": "simulation"},
        handler_identity="runmantle.demo.simulate_recovery:v1",
        handler_configuration={"mode": "simulation"},
    )
    health_provider = FakeHealthEvidenceProvider(fake_runtime)
    health_postcondition = RecoveryPostcondition(
        name="health-restored",
        description="Read health independently after the retry receipt.",
        provider=health_provider,
        evidence_type="health_signal",
    )
    plan = RecoveryPlan(
        plan_id=f"{incident.incident_id}-recovery-plan",
        task_id=diagnosis_contract.task_id,
        actions=(action,),
        proposed_by=diagnosis_worker.id,
        failure_diagnosis="The first persisted health observation was unhealthy.",
        context_reference=f"task:{diagnosis_contract.task_id}:reported-output",
        risk_level=RiskLevel.LOW,
        approval_required=True,
        preconditions=(
            RecoveryPrecondition(
                name="simulation-and-idempotency-boundary",
                description="Only the exact simulation retry may execute.",
                evaluator=lambda plan, action, contract: (
                    plan.task_id == contract.task_id
                    and action.parameters.get("mode") == "simulation"
                    and action.idempotency_key == contract.idempotency_key
                ),
            ),
        ),
        postconditions=(health_postcondition,),
        compensation_id="demo.reset_fake_runtime",
        created_at=clock(),
    )

    async def simulate_recovery(
        recovery_action: RecoveryAction,
        contract: TaskContract[Any, Any],
    ) -> None:
        del contract
        fake_runtime.execute_simulated_recovery(recovery_action)

    def recovery_executor(instance_id: str) -> DurableRecoveryExecutor:
        return DurableRecoveryExecutor(
            store=SQLiteStore(database_path),
            registry=CapabilityRegistry.with_standard_recovery_capabilities(),
            policy=RecoveryPolicy(
                allowed_capabilities=frozenset({StandardCapability.RETRY}),
                allowed_task_states=frozenset({TaskStatus.FAILED}),
                maximum_risk_level=RiskLevel.LOW,
                approval_required_capabilities=frozenset({StandardCapability.RETRY}),
                require_runtime_confirmation=True,
            ),
            handlers={
                StandardCapability.RETRY: RecoveryHandlerRegistration(
                    handler=simulate_recovery,
                    handler_identity="runmantle.demo.simulate_recovery:v1",
                    handler_configuration={"mode": "simulation"},
                )
            },
            evidence_providers=EvidenceProviderRegistry(
                (
                    EvidenceProviderRegistration(
                        provider=health_provider,
                        provider_identity=str(health_postcondition.provider_identity),
                        provider_configuration=(
                            health_postcondition.provider_configuration
                        ),
                        trust_level=EvidenceTrustLevel.INDEPENDENT,
                        acquisition_method=(
                            EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER
                        ),
                    ),
                )
            ),
            verifier=RuleBasedVerifier(clock=clock),
            event_sink=sink,
            clock=clock,
            id_factory=DeterministicIds("recovery-receipt"),
            instance_id=instance_id,
        )

    confirmation = fake_runtime.confirm(action)
    blocked_recovery = await recovery_executor("recovery-process-one").execute(
        plan,
        contract=diagnosis_contract,
        preflight_confirmation=confirmation,
    )
    executions_after_block = fake_runtime.simulated_recovery_executions

    # A later authenticated application boundary records the decision. It uses
    # a newly opened store and the exact immutable request hash.
    approval_store = SQLiteStore(database_path)
    pending = approval_store.load_approval(f"recovery:{plan.plan_id}:approval")
    approval = ApprovalDecision(
        decision_id=f"{plan.plan_id}-decision",
        approval_id=pending.request.approval_id,
        request_hash=pending.request.request_hash,
        approved=True,
        approver=ApproverIdentity(
            subject="demo-policy-owner",
            issuer="demo-auth-boundary",
            authenticated_at=clock(),
            authentication_method="demo-mfa",
            claims={"role": "incident-commander"},
        ),
        decided_at=clock(),
        reason="Approved the exact persisted simulation recovery plan.",
        metadata={"incident_id": incident.incident_id},
    )
    _, approval_event = approval_store.record_approval_decision(approval)
    if approval_event is not None:
        sink.emit(approval_event)

    confirmed_recovery = await recovery_executor("recovery-process-two").execute(
        plan,
        contract=diagnosis_contract,
    )
    final_runtime = DurableRuntime(
        database_path=database_path,
        verifier=RuleBasedVerifier(clock=clock),
        event_sink=sink,
        clock=clock,
    )
    final_diagnosis = await final_runtime.resume(
        diagnosis_contract.task_id,
        contract=diagnosis_contract,
    )
    sink.flush()
    sink.close()
    if sink.failures():
        raise RuntimeError(f"CortexOps export failed: {sink.failures()!r}")

    return IncidentResponseDemoResult(
        incident=incident,
        triage=triage,
        initial_diagnosis=initial_diagnosis,
        blocked_recovery=blocked_recovery,
        confirmed_recovery=confirmed_recovery,
        recovery_executions_after_block=executions_after_block,
        simulated_recovery_executions=(fake_runtime.simulated_recovery_executions),
        final_diagnosis=final_diagnosis,
        runtime_confirmation=confirmation,
        approval=approval,
        event_path=output_path,
        exported_events=_read_exported_events(output_path),
    )
