"""Subprocess probe used by the durable restart regression matrix."""

from __future__ import annotations

import asyncio
import json
import runpy
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from runmantle import (
    ActionPolicyDecision,
    ApprovalCriterion,
    CapabilityDeclaration,
    CheckpointRecord,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    PreActionAuthorization,
    RiskLevel,
    RuleBasedVerifier,
    RuntimeConfirmation,
    RuntimeConfirmationCriterion,
    SQLiteStore,
    StandardCapability,
    TaskContext,
    TaskContract,
    TaskStatus,
    VerificationResult,
    VerificationStatus,
    WorkerReport,
    WorkerReportedStatus,
)
from runmantle.evidence import _establish_evidence_origin

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]


def contract(mode: str) -> TaskContract[dict[str, Any], dict[str, Any]]:
    criteria: tuple[Any, ...] = (
        FieldEqualsCriterion(
            "value", "Value must match.", "value", 8 if mode == "failed" else 7
        ),
    )
    required_evidence: tuple[EvidenceRequirement, ...] = (
        EvidenceRequirement(
            "runtime_observation",
            "Runtime-established process-boundary evidence.",
        ),
    )
    if mode == "awaiting_approval":
        criteria = (ApprovalCriterion("approved", "Approval is required.", "owner"),)
    elif mode == "awaiting_runtime_confirmation":
        criteria = (
            RuntimeConfirmationCriterion(
                "confirmed", "Runtime confirmation is required.", "effect-1"
            ),
        )
    return TaskContract(
        task_id=f"subprocess-{mode}",
        objective="Exercise a durable process boundary.",
        input={},
        acceptance_criteria=criteria,
        required_evidence=required_evidence,
        allowed_capabilities=frozenset({"identity", StandardCapability.CHECKPOINT}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"subprocess-{mode}-once",
    )


def worker(effect_path: Path, *, checkpointed: bool = False) -> Any:
    class Worker:
        id = "subprocess-worker"
        name = "Subprocess worker"
        role = "test"
        version = "1.0.0"
        capabilities = (
            CapabilityDeclaration("identity", "Return a deterministic value."),
            CapabilityDeclaration(
                StandardCapability.CHECKPOINT, "Resume an explicit checkpoint."
            ),
        )

        async def execute(self, task: Any, context: TaskContext) -> WorkerReport[Any]:
            del task, context
            effect_path.parent.mkdir(parents=True, exist_ok=True)
            with effect_path.open("a", encoding="utf-8") as stream:
                stream.write("execute\n")
            return WorkerReport.completed({"value": 7})

        async def resume(
            self,
            task: Any,
            context: TaskContext,
            checkpoint: CheckpointRecord,
        ) -> WorkerReport[Any]:
            del task, context
            if not checkpointed:
                raise AssertionError("unexpected checkpoint resume")
            with effect_path.open("a", encoding="utf-8") as stream:
                stream.write("checkpoint\n")
            return WorkerReport.completed(dict(checkpoint.payload))

    return Worker()


def summary(
    path: Path,
    task_id: str,
    *,
    status: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    store = SQLiteStore(path)
    task = store.load_task(task_id)
    effects = (
        path.with_suffix(".effects").read_text(encoding="utf-8").splitlines()
        if path.with_suffix(".effects").exists()
        else []
    )
    print(
        json.dumps(
            {
                "status": status or task.status.value,
                "events": len(store.event_history(task_id)),
                "effects": effects,
                **(details or {}),
            }
        )
    )


async def task_phase(phase: str, path: Path, mode: str) -> None:
    task_contract = contract(mode)
    runtime = DurableRuntime(
        database_path=path,
        verifier=RuleBasedVerifier(clock=lambda: NOW),
        clock=lambda: NOW,
    )
    task_worker = worker(
        path.with_suffix(".effects"), checkpointed=mode == "checkpoint"
    )

    def add_observation() -> None:
        runtime.store.record_evidence(
            task_contract.task_id,
            _establish_evidence_origin(
                EvidenceItem(
                    "runtime-observation",
                    "runtime_observation",
                    "subprocess-runtime",
                    NOW,
                    payload={"observed": True},
                ),
                boundary="subprocess_runtime",
                provider_identity="tests.restart_probe:v1",
                provider_configuration={"scenario": mode},
                trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
            ),
        )

    if phase == "seed":
        if mode in {"pending", "checkpoint", "agent_reported_complete"}:
            pending = runtime.start(task_worker, task_contract)
            if mode == "checkpoint":
                runtime.store.transition(
                    task_contract.task_id,
                    expected_version=pending.version,
                    next_status=TaskStatus.RUNNING,
                    occurred_at=NOW,
                )
                runtime.store.save_checkpoint(
                    task_contract.task_id,
                    checkpoint_id="checkpoint-1",
                    payload={"value": 7},
                    label="safe-boundary",
                    occurred_at=NOW,
                )
            elif mode == "agent_reported_complete":
                running, _ = runtime.store.transition(
                    task_contract.task_id,
                    expected_version=pending.version,
                    next_status=TaskStatus.RUNNING,
                    occurred_at=NOW,
                )
                runtime.store.record_worker_report(
                    task_contract.task_id,
                    expected_version=running.version,
                    reported_status=WorkerReportedStatus.COMPLETED,
                    output={"value": 7},
                    errors=(),
                    occurred_at=NOW,
                )
        elif mode == "inconclusive":
            pending = runtime.start(task_worker, task_contract)
            running, _ = runtime.store.transition(
                task_contract.task_id,
                expected_version=pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=NOW,
            )
            reported, _ = runtime.store.record_worker_report(
                task_contract.task_id,
                expected_version=running.version,
                reported_status=WorkerReportedStatus.COMPLETED,
                output={"value": 7},
                errors=(),
                occurred_at=NOW,
            )
            verifying, _ = runtime.store.transition(
                task_contract.task_id,
                expected_version=reported.version,
                next_status=TaskStatus.VERIFYING,
                occurred_at=NOW,
            )
            runtime.store.record_verification(
                task_contract.task_id,
                expected_version=verifying.version,
                result=VerificationResult(status=VerificationStatus.INCONCLUSIVE),
                final_status=TaskStatus.INCONCLUSIVE,
                errors=(),
                occurred_at=NOW,
                wait_token=None,
            )
        elif mode == "awaiting_evidence":
            await runtime.execute(task_worker, task_contract)
        else:
            runtime.start(task_worker, task_contract)
            add_observation()
            await runtime.resume(
                task_contract.task_id,
                worker=task_worker,
                contract=task_contract,
            )
    else:
        if (
            mode
            in {
                "pending",
                "checkpoint",
                "agent_reported_complete",
                "awaiting_evidence",
                "inconclusive",
            }
            and phase == "resume"
        ):
            add_observation()
        elif mode == "awaiting_approval" and phase == "resume":
            runtime.decide_approval(
                task_contract.task_id,
                approval_key="owner",
                approved=True,
                approved_by="owner",
                reason="approved",
                approval_id="approval-1",
            )
        elif mode == "awaiting_runtime_confirmation" and phase == "resume":
            runtime.add_runtime_confirmation(
                task_contract.task_id,
                RuntimeConfirmation(
                    "confirmation-1",
                    "effect-1",
                    "identity",
                    task_contract.idempotency_key,
                    True,
                    True,
                    NOW,
                    "subprocess",
                    "observed",
                ),
            )
        await runtime.resume(
            task_contract.task_id,
            worker=task_worker if mode in {"pending", "checkpoint"} else None,
            contract=task_contract,
        )
    summary(path, task_contract.task_id)


async def action_phase(phase: str, path: Path) -> None:
    namespace = runpy.run_path(str(ROOT / "tests" / "test_actions.py"))
    task_contract = namespace["contract"]("subprocess-action")
    request = namespace["action_request"](task_contract.task_id)
    if phase == "seed":
        runtime = namespace["start_running"](path, task_contract)
        stored, _, _ = runtime.store.prepare_action(
            request, dry_run=False, occurred_at=NOW
        )
        stored, _ = runtime.store.record_action_policy(
            request.action_id,
            expected_version=stored.version,
            decision=ActionPolicyDecision(True, ("authorized",), False, NOW),
        )
        stored, _ = runtime.store.record_action_authorization(
            request.action_id,
            expected_version=stored.version,
            authorization=PreActionAuthorization(True, "authorized", (), None, NOW),
        )
        runtime.store.mark_action_executing(
            request.action_id,
            expected_version=stored.version,
            occurred_at=NOW,
            owner_id="dead-process",
        )
    else:

        async def handler(arguments: Any, cancellation: Any) -> Any:
            del arguments, cancellation
            with path.with_suffix(".effects").open("a", encoding="utf-8") as stream:
                stream.write("action\n")
            return {"ok": True}

        result = await namespace["action_executor"](SQLiteStore(path)).execute(
            request, contract=task_contract, handler=handler
        )
        if result.action.status.value != "unknown":
            raise AssertionError(result.action.status)
    summary(
        path,
        task_contract.task_id,
        status=SQLiteStore(path).load_action(request.action_id).status.value,
    )


async def action_postcondition_phase(phase: str, path: Path) -> None:
    namespace = runpy.run_path(str(ROOT / "tests" / "test_actions.py"))

    class ProcessEvidenceProvider:
        async def acquire(self, request: Any, receipt: Any) -> EvidenceItem:
            del request, receipt
            with path.with_suffix(".effects").open("a", encoding="utf-8") as stream:
                stream.write("postcondition\n")
            return EvidenceItem(
                "process-postcondition-evidence",
                "external_state",
                "subprocess-postcondition-provider",
                NOW,
                payload={"complete": True},
            )

    provider = ProcessEvidenceProvider()
    postcondition = namespace["Postcondition"](
        "observe-external-state",
        "Observe the external state in a later process.",
        provider,
        evidence_type="external_state",
        provider_identity="tests.restart_probe.process_provider:v1",
        provider_configuration={"scenario": "postcondition-restart"},
    )
    task_contract = namespace["contract"](
        "subprocess-action-postcondition",
        required_evidence=(
            EvidenceRequirement(
                "external_state",
                "Runtime-observed external state.",
            ),
        ),
        criteria=(
            FieldEqualsCriterion(
                "external-complete",
                "The external state is complete.",
                "complete",
                True,
                evidence_type="external_state",
            ),
        ),
    )
    request = replace(
        namespace["action_request"](task_contract.task_id),
        postconditions=(postcondition,),
    )
    registry = namespace["EvidenceProviderRegistry"](
        (
            namespace["EvidenceProviderRegistration"](
                provider=provider,
                provider_identity=str(postcondition.provider_identity),
                provider_configuration=postcondition.provider_configuration,
                trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
            ),
        )
    )
    if phase == "seed":
        runtime = namespace["start_running"](path, task_contract)
        stored, _, _ = runtime.store.prepare_action(
            request, dry_run=False, occurred_at=NOW
        )
        stored, _ = runtime.store.record_action_policy(
            request.action_id,
            expected_version=stored.version,
            decision=ActionPolicyDecision(True, ("authorized",), False, NOW),
        )
        stored, _ = runtime.store.record_action_authorization(
            request.action_id,
            expected_version=stored.version,
            authorization=PreActionAuthorization(True, "authorized", (), None, NOW),
        )
        stored, _ = runtime.store.mark_action_executing(
            request.action_id,
            expected_version=stored.version,
            occurred_at=NOW,
            owner_id="process-before-postconditions",
        )
        runtime.store.finish_action(
            request.action_id,
            expected_version=stored.version,
            receipt=namespace["ActionReceipt"](
                receipt_id="persisted-action-receipt",
                action_id=request.action_id,
                executor_id="subprocess-action-executor",
                status=namespace["ActionExecutionStatus"].EXECUTOR_SUCCEEDED,
                action_hash=request.action_hash,
                input_hash=request.input_hash,
                idempotency_key=request.idempotency_key,
                started_at=NOW,
                finished_at=NOW,
                output={"acknowledged": True},
            ),
        )
    else:

        async def handler(arguments: Any, cancellation: Any) -> Any:
            del arguments, cancellation
            with path.with_suffix(".effects").open("a", encoding="utf-8") as stream:
                stream.write("action\n")
            return {"acknowledged": True}

        await namespace["action_executor"](
            SQLiteStore(path),
            evidence_providers=registry,
        ).execute(request, contract=task_contract, handler=handler)
    action = SQLiteStore(path).load_action(request.action_id)
    summary(
        path,
        task_contract.task_id,
        status=action.status.value,
        details={"postcondition_status": action.postcondition_status.value},
    )


async def recovery_phase(phase: str, path: Path, mode: str) -> None:
    namespace = runpy.run_path(str(ROOT / "tests" / "test_durable_recovery.py"))
    task_id = f"subprocess-recovery-{mode}"
    task_contract = namespace["contract"](task_id)
    recovery_plan = namespace["plan"](task_contract, approval_required=mode == "pause")
    if phase == "seed":
        await namespace["awaiting_task"](path, task_id)
        if mode == "pause":
            await namespace["executor"](SQLiteStore(path), []).execute(
                recovery_plan,
                contract=task_contract,
                preflight_confirmation=namespace["confirmation"](recovery_plan),
            )
        else:
            store = SQLiteStore(path)
            store.save_runtime_confirmation(
                task_id, namespace["confirmation"](recovery_plan)
            )
            state = store.save_recovery_state(
                recovery_plan, status="planned", occurred_at=namespace["NOW"]
            )
            state = store.save_recovery_state(
                recovery_plan,
                status="authorized",
                occurred_at=namespace["NOW"],
                expected_version=state.version,
            )
            store.claim_recovery_execution(
                recovery_plan,
                expected_version=state.version,
                owner_id="dead-process",
                occurred_at=namespace["NOW"],
            )
    else:
        calls: list[str] = []
        if mode == "pause" and phase == "resume":
            namespace["approve"](SQLiteStore(path), recovery_plan)
        result = await namespace["executor"](
            SQLiteStore(path), calls, instance_id=f"{phase}-process"
        ).execute(recovery_plan, contract=task_contract)
        if mode == "ambiguity" and result.status.value != "unknown":
            raise AssertionError(result.status)
        if calls:
            with path.with_suffix(".effects").open("a", encoding="utf-8") as stream:
                stream.write("recovery\n")
    final_state = SQLiteStore(path).load_recovery_state(recovery_plan.plan_id)
    assert final_state is not None
    summary(path, task_id, status=final_state.status)


async def main() -> None:
    phase, database, scenario = sys.argv[1:4]
    path = Path(database)
    if scenario == "action_unknown":
        await action_phase(phase, path)
    elif scenario == "action_postcondition_restart":
        await action_postcondition_phase(phase, path)
    elif scenario.startswith("recovery_"):
        await recovery_phase(phase, path, scenario.removeprefix("recovery_"))
    else:
        await task_phase(phase, path, scenario)


asyncio.run(main())
