from __future__ import annotations

import asyncio
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from runmantle import (
    ApprovalCriterion,
    CapabilityDeclaration,
    CheckpointRecord,
    ConcurrentUpdateError,
    CorruptStoreError,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    InvalidTransitionError,
    LifecycleEventType,
    PredicateCriterion,
    RecoveryAction,
    RecoveryApproval,
    RecoveryPlan,
    ResumeNotPossibleError,
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

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def task_contract(
    task_id: str,
    *,
    criteria: tuple[Any, ...] | None = None,
    required_evidence: tuple[EvidenceRequirement, ...] | None = None,
    capabilities: frozenset[str] = frozenset({"identity"}),
) -> TaskContract[int, int]:
    return TaskContract(
        task_id=task_id,
        objective="Return and durably verify the integer seven.",
        input=7,
        acceptance_criteria=criteria
        or (
            PredicateCriterion(
                name="is-seven",
                description="The persisted output must equal seven.",
                predicate=lambda output, evidence: output == 7,
            ),
        ),
        required_evidence=(
            required_evidence
            if required_evidence is not None
            else (
                EvidenceRequirement(
                    "runtime_observation",
                    "Runtime-established test observation.",
                ),
            )
        ),
        allowed_capabilities=capabilities,
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=1),
        idempotency_key=f"{task_id}-key",
        metadata={"contract_revision": 1},
    )


def identity_worker(calls: list[str]) -> FunctionWorker[int, int]:
    async def execute(
        task: TaskContract[int, int],
        context: TaskContext,
    ) -> WorkerReport[int]:
        calls.append(task.task_id)
        context.require_capability("identity")
        return WorkerReport.completed(task.input)

    return FunctionWorker(
        id="durable-identity-worker",
        name="Durable identity worker",
        role="test",
        version="1.0.0",
        capabilities=(
            CapabilityDeclaration(
                name="identity",
                description="Return a deterministic integer.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )


def add_runtime_observation(
    runtime: DurableRuntime,
    task_id: str,
    *,
    evidence_type: str = "runtime_observation",
    payload: dict[str, Any] | None = None,
) -> None:
    runtime.store.record_evidence(
        task_id,
        _establish_evidence_origin(
            EvidenceItem(
                f"{task_id}-{evidence_type}",
                evidence_type,
                "durable-test-runtime",
                NOW,
                payload=payload or {"observed": True},
            ),
            boundary="durable_test_runtime",
            provider_identity="tests.durable_runtime:v1",
            provider_configuration={"evidence_type": evidence_type},
            trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
            acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
        ),
    )


class ResumeWorker:
    id = "checkpoint-worker"
    name = "Checkpoint worker"
    role = "test"
    version = "1.0.0"
    capabilities = (
        CapabilityDeclaration(
            name="identity",
            description="Return a deterministic integer.",
            requires_runtime_confirmation=False,
        ),
        CapabilityDeclaration(
            name=StandardCapability.CHECKPOINT,
            description="Persist an explicit test checkpoint.",
            requires_runtime_confirmation=False,
        ),
    )

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def execute(
        self,
        task: TaskContract[int, int],
        context: TaskContext,
    ) -> WorkerReport[int]:
        raise AssertionError("a RUNNING task must not restart execute()")

    async def resume(
        self,
        task: TaskContract[int, int],
        context: TaskContext,
        checkpoint: CheckpointRecord,
    ) -> WorkerReport[int]:
        self.calls.append(checkpoint.checkpoint_id)
        return WorkerReport.completed(int(checkpoint.payload["output"]))


class DurableRuntimeRestartTest(unittest.IsolatedAsyncioTestCase):
    async def test_inconclusive_resume_reenters_verification(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract(
                "resume-inconclusive",
                required_evidence=(
                    EvidenceRequirement(
                        "runtime_observation",
                        "Runtime-observed verification evidence.",
                    ),
                ),
            )
            runtime = DurableRuntime(database_path=path, clock=lambda: NOW)
            pending = runtime.start(identity_worker([]), contract)
            running, _ = runtime.store.transition(
                contract.task_id,
                expected_version=pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=NOW,
            )
            reported, _ = runtime.store.record_worker_report(
                contract.task_id,
                expected_version=running.version,
                reported_status=WorkerReportedStatus.COMPLETED,
                output=7,
                errors=(),
                occurred_at=NOW,
            )
            verifying, _ = runtime.store.transition(
                contract.task_id,
                expected_version=reported.version,
                next_status=TaskStatus.VERIFYING,
                occurred_at=NOW,
            )
            inconclusive, _ = runtime.store.record_verification(
                contract.task_id,
                expected_version=verifying.version,
                result=VerificationResult(status=VerificationStatus.INCONCLUSIVE),
                final_status=TaskStatus.INCONCLUSIVE,
                errors=(),
                occurred_at=NOW,
                wait_token=None,
            )
            self.assertEqual(inconclusive.status, TaskStatus.INCONCLUSIVE)
            runtime.store.record_evidence(
                contract.task_id,
                _establish_evidence_origin(
                    EvidenceItem(
                        "runtime-observation",
                        "runtime_observation",
                        "durable-test-runtime",
                        NOW,
                        payload={"observed": True},
                    ),
                    boundary="durable_test_runtime",
                    provider_identity="tests.runtime_observation:v1",
                    provider_configuration={"fixture": True},
                    trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
                    acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
                ),
            )

            result = await DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(clock=lambda: NOW),
                clock=lambda: NOW,
            ).resume(contract.task_id, contract=contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            transitions = [
                event
                for event in SQLiteStore(path).event_history(contract.task_id)
                if event.event_type is LifecycleEventType.STATE_TRANSITION
            ]
            self.assertEqual(transitions[-2].state, TaskStatus.VERIFYING)
            self.assertEqual(transitions[-1].state, TaskStatus.VERIFIED)

    async def test_concurrent_resume_does_not_invoke_worker_twice(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("concurrent-resume")
            started = asyncio.Event()
            release = asyncio.Event()
            calls: list[str] = []

            async def execute(
                task: TaskContract[int, int],
                context: TaskContext,
            ) -> WorkerReport[int]:
                calls.append(task.task_id)
                started.set()
                await release.wait()
                return WorkerReport.completed(task.input)

            worker = FunctionWorker(
                id="blocking-worker",
                name="Blocking worker",
                role="test",
                version="1.0.0",
                capabilities=(
                    CapabilityDeclaration(
                        name="identity",
                        description="Block at a deterministic test boundary.",
                    ),
                ),
                handler=execute,
            )
            first_runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            first_runtime.start(worker, contract)
            add_runtime_observation(first_runtime, contract.task_id)
            first = asyncio.create_task(
                first_runtime.resume(
                    contract.task_id,
                    worker=worker,
                    contract=contract,
                )
            )
            await started.wait()

            with self.assertRaises(ResumeNotPossibleError):
                await DurableRuntime(
                    database_path=path,
                    verifier=RuleBasedVerifier(),
                ).resume(contract.task_id, worker=worker, contract=contract)
            release.set()
            result = await first

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            self.assertEqual(calls, [contract.task_id])

    async def test_restart_from_pending_and_duplicate_resume_is_idempotent(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("pending-restart")
            calls: list[str] = []
            worker = identity_worker(calls)
            DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            ).start(worker, contract, correlation_id="pending-session")

            restarted = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            add_runtime_observation(restarted, contract.task_id)
            result = await restarted.resume(
                contract.task_id,
                worker=worker,
                contract=contract,
            )
            event_count = len(restarted.event_history(contract.task_id))
            duplicate = await DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            ).resume(contract.task_id, worker=worker, contract=contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            self.assertEqual(duplicate.status, TaskStatus.VERIFIED)
            self.assertEqual(calls, [contract.task_id])
            self.assertEqual(
                len(restarted.event_history(contract.task_id)),
                event_count,
            )

    async def test_restart_from_agent_reported_complete_and_verifying(self) -> None:
        for state in (
            TaskStatus.AGENT_REPORTED_COMPLETE,
            TaskStatus.VERIFYING,
        ):
            with self.subTest(state=state), TemporaryDirectory() as directory:
                path = Path(directory) / "runtime.db"
                contract = task_contract(f"restart-{state.value}")
                worker = identity_worker([])
                runtime = DurableRuntime(database_path=path)
                pending = runtime.start(worker, contract)
                running, _ = runtime.store.transition(
                    contract.task_id,
                    expected_version=pending.version,
                    next_status=TaskStatus.RUNNING,
                    occurred_at=NOW,
                )
                reported, _ = runtime.store.record_worker_report(
                    contract.task_id,
                    expected_version=running.version,
                    reported_status=WorkerReportedStatus.COMPLETED,
                    output=7,
                    errors=(),
                    occurred_at=NOW,
                )
                if state is TaskStatus.VERIFYING:
                    runtime.store.transition(
                        contract.task_id,
                        expected_version=reported.version,
                        next_status=TaskStatus.VERIFYING,
                        occurred_at=NOW,
                    )
                add_runtime_observation(runtime, contract.task_id)

                result = await DurableRuntime(
                    database_path=path,
                    verifier=RuleBasedVerifier(),
                ).resume(contract.task_id, contract=contract)

                self.assertEqual(result.status, TaskStatus.VERIFIED)

    async def test_evidence_survives_restart_and_continues_verification(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract(
                "evidence-restart",
                criteria=(
                    FieldEqualsCriterion(
                        name="evidence-is-seven",
                        description="Evidence must contain seven.",
                        field_path="value",
                        expected=7,
                        evidence_type="receipt",
                    ),
                ),
                required_evidence=(
                    EvidenceRequirement("receipt", "A durable result receipt."),
                ),
            )
            worker = identity_worker([])
            initial = await DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            ).execute(worker, contract)
            self.assertEqual(initial.status, TaskStatus.AWAITING_EVIDENCE)

            unchanged_runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            event_count = len(unchanged_runtime.event_history(contract.task_id))
            unchanged = await unchanged_runtime.resume(
                contract.task_id,
                contract=contract,
            )
            self.assertEqual(unchanged.status, TaskStatus.AWAITING_EVIDENCE)
            self.assertEqual(
                len(unchanged_runtime.event_history(contract.task_id)),
                event_count,
            )

            restarted = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            add_runtime_observation(
                restarted,
                contract.task_id,
                evidence_type="receipt",
                payload={"value": 7},
            )
            result = await restarted.resume(contract.task_id, contract=contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            self.assertEqual(len(result.evidence), 1)
            reopened = SQLiteStore(path)
            self.assertEqual(len(reopened.evidence(contract.task_id)), 1)
            sequences = [
                event.sequence for event in reopened.event_history(contract.task_id)
            ]
            self.assertEqual(sequences, list(range(1, len(sequences) + 1)))

    async def test_verified_task_rejects_late_evidence_transactionally(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("verified-evidence-is-immutable")
            runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            runtime.start(identity_worker([]), contract)
            add_runtime_observation(runtime, contract.task_id)
            result = await runtime.resume(
                contract.task_id,
                worker=identity_worker([]),
                contract=contract,
            )
            self.assertEqual(result.status, TaskStatus.VERIFIED)

            before = runtime.load_task(contract.task_id)
            event_count = len(runtime.event_history(contract.task_id))
            with self.assertRaises(InvalidTransitionError):
                runtime.add_evidence(
                    contract.task_id,
                    EvidenceItem(
                        evidence_id="too-late",
                        type="receipt",
                        source="test-runtime",
                        collected_at=NOW,
                        payload={"value": 7},
                    ),
                )

            after = runtime.load_task(contract.task_id)
            self.assertEqual(after.version, before.version)
            self.assertEqual(len(runtime.event_history(contract.task_id)), event_count)
            self.assertEqual(len(runtime.store.evidence(contract.task_id)), 1)

    async def test_approval_survives_restart_and_continues_verification(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract(
                "approval-restart",
                criteria=(
                    ApprovalCriterion(
                        name="release-approved",
                        description="The release owner must approve.",
                        approval_key="release-owner",
                    ),
                ),
            )
            worker = identity_worker([])
            initial_runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            initial_runtime.start(worker, contract)
            add_runtime_observation(initial_runtime, contract.task_id)
            initial = await initial_runtime.resume(
                contract.task_id,
                worker=worker,
                contract=contract,
            )
            self.assertEqual(initial.status, TaskStatus.AWAITING_APPROVAL)

            restarted = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            restarted.decide_approval(
                contract.task_id,
                approval_key="release-owner",
                approved=True,
                approved_by="owner@example.test",
                reason="Reviewed deterministic evidence.",
                approval_id="approval-1",
            )
            result = await restarted.resume(contract.task_id, contract=contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            self.assertTrue(SQLiteStore(path).approvals(contract.task_id)[0].approved)

    async def test_runtime_confirmation_survives_restart_and_continues(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract(
                "confirmation-restart",
                criteria=(
                    RuntimeConfirmationCriterion(
                        name="effect-confirmed",
                        description="The runtime must confirm the exact effect.",
                        confirmation_key="effect-1",
                    ),
                ),
            )
            worker = identity_worker([])
            initial_runtime = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            initial_runtime.start(worker, contract)
            add_runtime_observation(initial_runtime, contract.task_id)
            initial = await initial_runtime.resume(
                contract.task_id,
                worker=worker,
                contract=contract,
            )
            self.assertEqual(
                initial.status,
                TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
            )

            restarted = DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            )
            restarted.add_runtime_confirmation(
                contract.task_id,
                RuntimeConfirmation(
                    confirmation_id="confirmation-1",
                    action_id="effect-1",
                    capability="identity",
                    idempotency_key=contract.idempotency_key,
                    supported=True,
                    safe=True,
                    confirmed_at=NOW,
                    confirmed_by="test-runtime",
                    reason="The exact test effect was observed.",
                ),
            )
            result = await restarted.resume(contract.task_id, contract=contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)

    async def test_running_task_resumes_only_from_explicit_checkpoint(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract(
                "checkpoint-restart",
                capabilities=frozenset({"identity", StandardCapability.CHECKPOINT}),
            )
            calls: list[str] = []
            worker = ResumeWorker(calls)
            runtime = DurableRuntime(database_path=path)
            pending = runtime.start(worker, contract)
            running, _ = runtime.store.transition(
                contract.task_id,
                expected_version=pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=NOW,
            )
            checkpoint, _ = runtime.store.save_checkpoint(
                contract.task_id,
                checkpoint_id="checkpoint-1",
                payload={"output": 7},
                label="after-external-read",
                occurred_at=NOW,
            )
            self.assertGreater(checkpoint.task_version, running.version)
            add_runtime_observation(runtime, contract.task_id)

            result = await DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            ).resume(contract.task_id, worker=worker, contract=contract)
            duplicate = await DurableRuntime(
                database_path=path,
                verifier=RuleBasedVerifier(),
            ).resume(contract.task_id, worker=worker, contract=contract)

            self.assertEqual(result.status, TaskStatus.VERIFIED)
            self.assertEqual(duplicate.status, TaskStatus.VERIFIED)
            self.assertEqual(calls, ["checkpoint-1"])
            self.assertEqual(len(SQLiteStore(path).checkpoints(contract.task_id)), 1)


class SQLiteStoreInvariantTest(unittest.TestCase):
    def test_concurrent_transitions_have_one_winner(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("concurrent-transition")
            runtime = DurableRuntime(database_path=path)
            pending = runtime.start(identity_worker([]), contract)

            def transition() -> str:
                try:
                    SQLiteStore(path).transition(
                        contract.task_id,
                        expected_version=pending.version,
                        next_status=TaskStatus.RUNNING,
                        occurred_at=NOW,
                    )
                    return "won"
                except ConcurrentUpdateError:
                    return "conflict"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = sorted(executor.map(lambda _: transition(), range(2)))

            self.assertEqual(outcomes, ["conflict", "won"])
            self.assertEqual(SQLiteStore(path).load_task(contract.task_id).version, 2)

    def test_invalid_transition_is_rejected_transactionally(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("invalid-transition")
            runtime = DurableRuntime(database_path=path)
            pending = runtime.start(identity_worker([]), contract)
            events_before = runtime.event_history(contract.task_id)

            with self.assertRaises(InvalidTransitionError):
                runtime.store.transition(
                    contract.task_id,
                    expected_version=pending.version,
                    next_status=TaskStatus.VERIFIED,
                    occurred_at=NOW,
                )

            loaded = SQLiteStore(path).load_task(contract.task_id)
            self.assertEqual(loaded.status, TaskStatus.PENDING)
            self.assertEqual(loaded.version, pending.version)
            self.assertEqual(runtime.event_history(contract.task_id), events_before)

    def test_verified_requires_authoritative_verification_commit(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("verified-transition-boundary")
            runtime = DurableRuntime(database_path=path, clock=lambda: NOW)
            pending = runtime.start(identity_worker([]), contract)
            running, _ = runtime.store.transition(
                contract.task_id,
                expected_version=pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=NOW,
            )
            reported, _ = runtime.store.record_worker_report(
                contract.task_id,
                expected_version=running.version,
                reported_status=WorkerReportedStatus.COMPLETED,
                output=7,
                errors=(),
                occurred_at=NOW,
            )
            verifying, _ = runtime.store.transition(
                contract.task_id,
                expected_version=reported.version,
                next_status=TaskStatus.VERIFYING,
                occurred_at=NOW,
            )
            events_before = runtime.event_history(contract.task_id)

            with self.assertRaisesRegex(
                InvalidTransitionError,
                "record_verification",
            ):
                runtime.store.transition(
                    contract.task_id,
                    expected_version=verifying.version,
                    next_status=TaskStatus.VERIFIED,
                    occurred_at=NOW,
                )

            unchanged = SQLiteStore(path).load_task(contract.task_id)
            self.assertEqual(unchanged.status, TaskStatus.VERIFYING)
            self.assertEqual(unchanged.version, verifying.version)
            self.assertIsNone(unchanged.verification)
            self.assertEqual(runtime.store.evidence(contract.task_id).items, ())
            self.assertEqual(runtime.event_history(contract.task_id), events_before)

            add_runtime_observation(runtime, contract.task_id)
            with_evidence = runtime.store.load_task(contract.task_id)
            verified, _ = runtime.store.record_verification(
                contract.task_id,
                expected_version=with_evidence.version,
                result=VerificationResult(status=VerificationStatus.VERIFIED),
                final_status=TaskStatus.VERIFIED,
                errors=(),
                occurred_at=NOW,
                wait_token=None,
            )

            self.assertEqual(verified.status, TaskStatus.VERIFIED)
            self.assertIsNotNone(verified.verification)

    def test_migrates_version_one_database_without_losing_tasks(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            legacy = SQLiteStore(path, target_schema_version=1)
            contract = task_contract("migration-task")
            legacy.create_task(
                contract,
                correlation_id="migration-session",
                worker_id="migration-worker",
                occurred_at=NOW,
            )
            self.assertEqual(legacy.schema_version, 1)

            migrated = SQLiteStore(path)

            self.assertEqual(migrated.schema_version, 7)
            self.assertEqual(
                migrated.load_task(contract.task_id).status, TaskStatus.PENDING
            )
            with sqlite3.connect(path) as connection:
                versions = connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
            self.assertEqual(
                versions,
                [(1,), (2,), (3,), (4,), (5,), (6,), (7,)],
            )

    def test_corrupt_persisted_json_and_status_are_rejected(self) -> None:
        for column, value in (
            ("contract_json", "{not-json"),
            ("contract_digest", "0" * 64),
            ("current_state", "invented-state"),
        ):
            with self.subTest(column=column), TemporaryDirectory() as directory:
                path = Path(directory) / "runtime.db"
                contract = task_contract(f"corrupt-{column}")
                DurableRuntime(database_path=path).start(identity_worker([]), contract)
                with sqlite3.connect(path) as connection:
                    connection.execute(
                        f"UPDATE tasks SET {column} = ? WHERE task_id = ?",
                        (value, contract.task_id),
                    )

                with self.assertRaises(CorruptStoreError):
                    SQLiteStore(path).load_task(contract.task_id)

    def test_recovery_and_idempotency_records_survive_restart(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            contract = task_contract("recovery-state")
            store = SQLiteStore(path)
            store.create_task(
                contract,
                correlation_id="recovery-session",
                worker_id="recovery-worker",
                occurred_at=NOW,
            )
            plan = RecoveryPlan(
                plan_id="plan-1",
                task_id=contract.task_id,
                proposed_by="recovery-worker",
                actions=(
                    RecoveryAction(
                        action_id="retry-1",
                        capability=StandardCapability.RETRY,
                        idempotency_key=contract.idempotency_key,
                        reason="Retry from a durable recovery boundary.",
                    ),
                ),
            )
            initial_recovery = store.save_recovery_state(
                plan,
                status="planned",
                occurred_at=NOW,
            )
            store.save_recovery_state(
                plan,
                status="awaiting_approval",
                occurred_at=NOW,
                expected_version=initial_recovery.version,
            )
            store.save_recovery_approval(
                contract.task_id,
                RecoveryApproval(
                    action_id="retry-1",
                    capability=StandardCapability.RETRY,
                    idempotency_key=contract.idempotency_key,
                    approved=True,
                    approved_by="recovery-owner",
                    reason="Approved exact durable retry.",
                ),
                occurred_at=NOW,
            )
            store.reserve_idempotency(
                scope="recovery",
                key=contract.idempotency_key,
                owner_id=plan.plan_id,
                occurred_at=NOW,
            )
            store.complete_idempotency(
                scope="recovery",
                key=contract.idempotency_key,
                owner_id=plan.plan_id,
                result={"status": "complete"},
                occurred_at=NOW,
            )

            reopened = SQLiteStore(path)
            recovery = reopened.load_recovery_state(plan.plan_id)
            idempotency = reopened.idempotency_record(
                scope="recovery",
                key=contract.idempotency_key,
            )
            self.assertIsNotNone(recovery)
            self.assertEqual(recovery.status if recovery else None, "awaiting_approval")
            self.assertEqual(idempotency.status if idempotency else None, "completed")
            approval = reopened.approvals(contract.task_id)[0]
            self.assertEqual(approval.capability, StandardCapability.RETRY)
            self.assertEqual(approval.idempotency_key, contract.idempotency_key)

    def test_stable_record_ids_cannot_cross_task_boundaries(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.db"
            store = SQLiteStore(path)
            first = task_contract(
                "record-owner-one",
                capabilities=frozenset({"identity", "checkpoint"}),
            )
            second = task_contract(
                "record-owner-two",
                capabilities=frozenset({"identity", "checkpoint"}),
            )
            first_pending, _ = store.create_task(
                first,
                correlation_id="owner-one",
                worker_id="worker-one",
                occurred_at=NOW,
            )
            second_pending, _ = store.create_task(
                second,
                correlation_id="owner-two",
                worker_id="worker-two",
                occurred_at=NOW,
            )
            store.transition(
                first.task_id,
                expected_version=first_pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=NOW,
            )
            second_running, _ = store.transition(
                second.task_id,
                expected_version=second_pending.version,
                next_status=TaskStatus.RUNNING,
                occurred_at=NOW,
            )
            store.save_checkpoint(
                first.task_id,
                checkpoint_id="shared-checkpoint",
                payload={"step": 1},
                label="safe-boundary",
                occurred_at=NOW,
            )
            store.request_approval(
                first.task_id,
                approval_id="shared-approval",
                approval_key="release",
                reason="first task",
                occurred_at=NOW,
            )
            confirmation = RuntimeConfirmation(
                confirmation_id="shared-confirmation",
                action_id="effect",
                capability="identity",
                idempotency_key="effect-key",
                supported=True,
                safe=True,
                confirmed_at=NOW,
                confirmed_by="runtime",
                reason="Observed exact effect.",
            )
            store.save_runtime_confirmation(first.task_id, confirmation)

            with self.assertRaises(ConcurrentUpdateError):
                store.save_checkpoint(
                    second.task_id,
                    checkpoint_id="shared-checkpoint",
                    payload={"step": 1},
                    label="safe-boundary",
                    occurred_at=NOW,
                )
            with self.assertRaises(InvalidTransitionError):
                store.claim_checkpoint_resume(
                    second.task_id,
                    checkpoint_id="shared-checkpoint",
                    expected_version=second_running.version,
                    occurred_at=NOW,
                )
            with self.assertRaises(ConcurrentUpdateError):
                store.request_approval(
                    second.task_id,
                    approval_id="shared-approval",
                    approval_key="release",
                    reason="second task",
                    occurred_at=NOW,
                )
            with self.assertRaises(ConcurrentUpdateError):
                store.decide_approval(
                    second.task_id,
                    approval_key="release",
                    approved=True,
                    approved_by="second-owner",
                    reason="wrong task",
                    occurred_at=NOW,
                    approval_id="shared-approval",
                )
            with self.assertRaises(ConcurrentUpdateError):
                store.save_runtime_confirmation(second.task_id, confirmation)

            self.assertEqual(store.load_task(second.task_id), second_running)

    def test_every_important_state_is_readable_after_reopen(self) -> None:
        important_states = (
            TaskStatus.PENDING,
            TaskStatus.RUNNING,
            TaskStatus.AGENT_REPORTED_COMPLETE,
            TaskStatus.VERIFYING,
            TaskStatus.AWAITING_EVIDENCE,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
            TaskStatus.INCONCLUSIVE,
            TaskStatus.VERIFIED,
            TaskStatus.FAILED,
        )
        with TemporaryDirectory() as directory:
            for target in important_states:
                with self.subTest(target=target):
                    path = Path(directory) / f"{target.value}.db"
                    contract = task_contract(f"state-{target.value}")
                    runtime = DurableRuntime(database_path=path)
                    pending = runtime.start(identity_worker([]), contract)
                    current = pending
                    if target is not TaskStatus.PENDING:
                        current, _ = runtime.store.transition(
                            contract.task_id,
                            expected_version=current.version,
                            next_status=TaskStatus.RUNNING,
                            occurred_at=NOW,
                        )
                    if target not in {TaskStatus.PENDING, TaskStatus.RUNNING}:
                        current, _ = runtime.store.record_worker_report(
                            contract.task_id,
                            expected_version=current.version,
                            reported_status=WorkerReportedStatus.COMPLETED,
                            output=7,
                            errors=(),
                            occurred_at=NOW,
                        )
                    if target not in {
                        TaskStatus.PENDING,
                        TaskStatus.RUNNING,
                        TaskStatus.AGENT_REPORTED_COMPLETE,
                    }:
                        current, _ = runtime.store.transition(
                            contract.task_id,
                            expected_version=current.version,
                            next_status=TaskStatus.VERIFYING,
                            occurred_at=NOW,
                        )
                    if target not in {
                        TaskStatus.PENDING,
                        TaskStatus.RUNNING,
                        TaskStatus.AGENT_REPORTED_COMPLETE,
                        TaskStatus.VERIFYING,
                    }:
                        verification_status = VerificationStatus(target.value)
                        if target is TaskStatus.VERIFIED:
                            add_runtime_observation(runtime, contract.task_id)
                            current = runtime.store.load_task(contract.task_id)
                        current, _ = runtime.store.record_verification(
                            contract.task_id,
                            expected_version=current.version,
                            result=VerificationResult(status=verification_status),
                            final_status=target,
                            errors=(),
                            occurred_at=NOW,
                            wait_token=None,
                        )

                    reopened = SQLiteStore(path).load_task(contract.task_id)
                    self.assertEqual(reopened.status, target)
                    self.assertEqual(reopened.version, current.version)
                    self.assertGreater(
                        len(SQLiteStore(path).event_history(contract.task_id)), 0
                    )
                    event_types = {
                        event.event_type
                        for event in SQLiteStore(path).event_history(contract.task_id)
                    }
                    self.assertIn(LifecycleEventType.STATE_TRANSITION, event_types)


if __name__ == "__main__":
    unittest.main()
