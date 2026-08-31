from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest

from runmantle import (
    ActionPolicy,
    ActionReceiptEvidenceProvider,
    CapabilityDeclaration,
    CapabilityRegistry,
    CorruptStoreError,
    DurableRuntime,
    EvidenceAcquisitionMethod,
    EvidenceCollection,
    EvidenceIntegrityError,
    EvidenceItem,
    EvidenceProviderRegistration,
    EvidenceProviderRegistry,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FileEvidenceProvider,
    FunctionWorker,
    InMemoryRuntime,
    InvalidTransitionError,
    MediatedActionExecutor,
    Postcondition,
    RiskLevel,
    RuleBasedVerifier,
    SafeFunctionTool,
    SQLiteStore,
    TaskContext,
    TaskContract,
    TaskStatus,
    VerificationResult,
    VerificationStatus,
    WorkerReport,
    WorkerReportedStatus,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
WRITE = "trust_test.write"


def independent_contract(
    task_id: str,
    *,
    evidence_type: str = "external_state",
    minimum_trust: EvidenceTrustLevel = EvidenceTrustLevel.INDEPENDENT,
    field_path: str = "complete",
    expected: Any = True,
) -> TaskContract[dict[str, Any], dict[str, Any]]:
    return TaskContract(
        task_id=task_id,
        objective="Prove the external outcome through the required trust boundary.",
        input={},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="external-complete",
                description="The externally observed state is complete.",
                field_path=field_path,
                expected=expected,
                evidence_type=evidence_type,
            ),
        ),
        required_evidence=(
            EvidenceRequirement(
                evidence_type=evidence_type,
                description="Trusted external outcome evidence.",
                minimum_trust_level=minimum_trust,
            ),
        ),
        allowed_capabilities=frozenset({WRITE}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}:once",
    )


def declared_contract(
    task_id: str,
    *,
    minimum_trust: EvidenceTrustLevel | None,
) -> TaskContract[dict[str, Any], dict[str, Any]]:
    requirements = (
        ()
        if minimum_trust is None
        else (
            EvidenceRequirement(
                evidence_type="external_state",
                description="Declared external outcome boundary.",
                minimum_trust_level=minimum_trust,
            ),
        )
    )
    return TaskContract(
        task_id=task_id,
        objective="Exercise the generic verification trust boundary.",
        input={},
        acceptance_criteria=(
            FieldEqualsCriterion(
                name="complete",
                description="The reported outcome is complete.",
                field_path="complete",
                expected=True,
                evidence_type=("external_state" if requirements else None),
            ),
        ),
        required_evidence=requirements,
        allowed_capabilities=frozenset(),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=2),
        idempotency_key=f"{task_id}:once",
    )


def established_evidence(trust_level: EvidenceTrustLevel) -> EvidenceItem:
    provider = object()
    registry = EvidenceProviderRegistry(
        (
            EvidenceProviderRegistration(
                provider=provider,
                provider_identity=f"tests.external_state:{trust_level.name.lower()}",
                provider_configuration={"fixture": True},
                trust_level=trust_level,
                acquisition_method=(
                    EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER
                    if trust_level is EvidenceTrustLevel.INDEPENDENT
                    else EvidenceAcquisitionMethod.RUNTIME_OBSERVED
                ),
            ),
        )
    )
    item = registry._establish(
        provider,
        EvidenceItem(
            evidence_id=f"established-{trust_level.name.lower()}",
            type="external_state",
            source="verification-boundary-fixture",
            collected_at=NOW,
            payload={"complete": True},
        ),
        boundary="verification_test_fixture",
        provider_identity=f"tests.external_state:{trust_level.name.lower()}",
        provider_configuration={"fixture": True},
    )
    assert item is not None
    return item


def worker_with_report(
    task_id: str,
    report: WorkerReport[dict[str, Any]],
) -> FunctionWorker[dict[str, Any], dict[str, Any]]:
    async def execute(
        contract: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del contract, context
        return report

    return FunctionWorker(
        id=f"{task_id}:worker",
        name="Adversarial evidence worker",
        role="test",
        version="1",
        capabilities=(
            CapabilityDeclaration(
                name=WRITE,
                description="Test-only mediated write.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )


def verifying_store(
    database: Path,
    contract: TaskContract[Any, Any],
) -> tuple[SQLiteStore, Any]:
    store = SQLiteStore(database)
    task, _ = store.create_task(
        contract,
        correlation_id=f"{contract.task_id}:correlation",
        worker_id="persistence-boundary-worker",
        occurred_at=NOW,
    )
    task, _ = store.transition(
        contract.task_id,
        expected_version=task.version,
        next_status=TaskStatus.RUNNING,
        occurred_at=NOW,
    )
    task, _ = store.record_worker_report(
        contract.task_id,
        expected_version=task.version,
        reported_status=WorkerReportedStatus.COMPLETED,
        output={"complete": True},
        errors=(),
        occurred_at=NOW,
    )
    return store, store.transition(
        contract.task_id,
        expected_version=task.version,
        next_status=TaskStatus.VERIFYING,
        occurred_at=NOW,
    )[0]


async def _worker_collector_cannot_record_independent_evidence() -> None:
    contract = independent_contract("collector-forgery")

    async def execute(
        supplied: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        del supplied
        item = context.evidence.record(
            "external_state",
            {"complete": True},
            source="malicious-worker",
            acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            trust_level=EvidenceTrustLevel.INDEPENDENT,
        )
        assert item.trust_level is EvidenceTrustLevel.AGENT_CLAIM
        return WorkerReport.completed({"ok": True})

    worker = FunctionWorker(
        id="collector-forger",
        name="Collector forger",
        role="test",
        version="1",
        capabilities=(
            CapabilityDeclaration(
                name=WRITE,
                description="Test-only declared capability.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        worker,
        contract,
    )

    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert (
        result.evidence[0].acquisition_method
        is EvidenceAcquisitionMethod.AGENT_REPORTED
    )
    assert not result.evidence[0].trust_established


async def _agent_reported_complete_is_never_success() -> None:
    result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
        worker_with_report(
            "reported-complete",
            WorkerReport.completed({"ok": True}),
        ),
        independent_contract("reported-complete"),
    )
    assert result.reported_status is WorkerReportedStatus.COMPLETED
    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert not result.succeeded


async def _manual_independent_evidence_object_is_not_trusted() -> None:
    item = EvidenceItem(
        evidence_id="manual-independent",
        type="external_state",
        source="worker-constructed-object",
        collected_at=NOW,
        payload={"complete": True},
        acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
        trust_level=EvidenceTrustLevel.INDEPENDENT,
    )
    assert item.trust_level is EvidenceTrustLevel.INDEPENDENT
    assert item.effective_trust_level is EvidenceTrustLevel.AGENT_CLAIM
    assert not item.trust_established

    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(clock=lambda: NOW)
    ).execute(
        worker_with_report(
            "manual-independent",
            WorkerReport.completed({"ok": True}, evidence=EvidenceCollection((item,))),
        ),
        independent_contract("manual-independent"),
    )
    assert result.status is TaskStatus.AWAITING_EVIDENCE


async def _agent_content_cannot_satisfy_independent_requirement() -> None:
    claim = EvidenceItem(
        evidence_id="plausible-agent-content",
        type="external_state",
        source="agent",
        collected_at=NOW,
        payload={"complete": True, "looks_authoritative": True},
    )
    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(clock=lambda: NOW)
    ).execute(
        worker_with_report(
            "agent-content",
            WorkerReport.completed({"ok": True}, evidence=EvidenceCollection((claim,))),
        ),
        independent_contract("agent-content"),
    )
    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert not result.succeeded


async def _worker_owned_registry_cannot_mint_through_public_api() -> None:
    provider = object()
    registry = EvidenceProviderRegistry(
        (
            EvidenceProviderRegistration(
                provider=provider,
                provider_identity="attacker.provider:v1",
                provider_configuration={"attacker_controlled": True},
                trust_level=EvidenceTrustLevel.INDEPENDENT,
                acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
            ),
        )
    )
    assert not hasattr(registry, "establish")
    forged = EvidenceItem(
        evidence_id="worker-registry-forgery",
        type="external_state",
        source="attacker",
        collected_at=NOW,
        payload={"complete": True},
        acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
        trust_level=EvidenceTrustLevel.INDEPENDENT,
    )

    result = await InMemoryRuntime(
        verifier=RuleBasedVerifier(clock=lambda: NOW)
    ).execute(
        worker_with_report(
            "worker-registry-forgery",
            WorkerReport.completed(
                {"ok": True}, evidence=EvidenceCollection((forged,))
            ),
        ),
        independent_contract("worker-registry-forgery"),
    )
    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert result.evidence[0].trust_level is EvidenceTrustLevel.AGENT_CLAIM
    assert not result.evidence[0].trust_established


async def _run_builtin_provider_flow(
    database: Path,
    contract: TaskContract[dict[str, Any], dict[str, Any]],
    provider: FileEvidenceProvider | ActionReceiptEvidenceProvider,
    handler: Any,
) -> Any:
    runtime = DurableRuntime(
        database_path=database,
        verifier=RuleBasedVerifier(clock=lambda: NOW),
        clock=lambda: NOW,
    )
    executor = MediatedActionExecutor(
        store=runtime.store,
        capabilities=CapabilityRegistry(
            (
                CapabilityDeclaration(
                    name=WRITE,
                    description="Test-only mediated write.",
                    requires_runtime_confirmation=False,
                ),
            )
        ),
        policy=ActionPolicy(
            allowed_capabilities=frozenset({WRITE}),
            maximum_risk_level=RiskLevel.LOW,
        ),
        clock=lambda: NOW,
    )
    tool = SafeFunctionTool(
        name="write",
        description="Perform the test write through the action boundary.",
        required_capability=WRITE,
        function=handler,
        executor=executor,
        postconditions=(
            Postcondition(
                name="observe",
                description="Observe the result after the executor receipt.",
                provider=provider,
                evidence_type=provider.evidence_type,
            ),
        ),
    )

    async def execute(
        supplied: TaskContract[dict[str, Any], dict[str, Any]],
        context: TaskContext,
    ) -> WorkerReport[dict[str, Any]]:
        action = await tool.invoke(
            contract=supplied,
            context=context,
            arguments={},
            idempotency_key=f"{supplied.task_id}:action",
        )
        assert action.action.receipt is not None
        return WorkerReport.completed({"ok": True})

    worker = FunctionWorker(
        id=f"{contract.task_id}:action-worker",
        name="Mediated action worker",
        role="test",
        version="1",
        capabilities=(
            CapabilityDeclaration(
                name=WRITE,
                description="Test-only mediated write.",
                requires_runtime_confirmation=False,
            ),
        ),
        handler=execute,
    )
    return await runtime.execute(worker, contract)


async def _executor_receipt_cannot_prove_independent_external_outcome() -> None:
    with TemporaryDirectory() as directory:
        result = await _run_builtin_provider_flow(
            Path(directory) / "runtime.db",
            independent_contract("receipt-only"),
            ActionReceiptEvidenceProvider(evidence_type="external_state"),
            lambda: {"complete": True},
        )

    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert result.evidence[0].trust_established
    assert (
        result.evidence[0].effective_trust_level is EvidenceTrustLevel.EXECUTOR_RECEIPT
    )
    assert result.evidence[0].trust_origin["boundary"] == (
        "mediated_action_postcondition"
    )


async def _builtin_file_provider_enforces_runtime_observation_boundary() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        artifact = root / "artifact.txt"

        def write() -> dict[str, bool]:
            artifact.write_text("complete", encoding="utf-8")
            return {"complete": True}

        result = await _run_builtin_provider_flow(
            root / "runtime.db",
            independent_contract(
                "builtin-file",
                evidence_type="file_state",
                minimum_trust=EvidenceTrustLevel.RUNTIME_OBSERVED,
                field_path="exists",
            ),
            FileEvidenceProvider(
                artifact,
                evidence_type="file_state",
                clock=lambda: NOW,
            ),
            write,
        )

    assert result.status is TaskStatus.VERIFIED
    assert result.evidence[0].trust_established
    assert (
        result.evidence[0].effective_trust_level is EvidenceTrustLevel.RUNTIME_OBSERVED
    )
    assert result.evidence[0].acquisition_method is (
        EvidenceAcquisitionMethod.FILESYSTEM_INSPECTION
    )


async def _trusted_origin_survives_persistence_restart() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        artifact = root / "artifact.txt"

        def write() -> dict[str, bool]:
            artifact.write_text("complete", encoding="utf-8")
            return {"complete": True}

        await _run_builtin_provider_flow(
            root / "runtime.db",
            independent_contract(
                "origin-restart",
                evidence_type="file_state",
                minimum_trust=EvidenceTrustLevel.RUNTIME_OBSERVED,
                field_path="exists",
            ),
            FileEvidenceProvider(
                artifact,
                evidence_type="file_state",
                clock=lambda: NOW,
            ),
            write,
        )
        restored = SQLiteStore(root / "runtime.db").evidence("origin-restart")[0]

    assert restored.trust_established
    assert restored.origin_hash is not None
    assert restored.trust_origin["boundary"] == "mediated_action_postcondition"
    assert restored.trust_origin["provider_identity"]


async def _persisted_trust_tampering_cannot_result_in_verified() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "runtime.db"
        artifact = root / "artifact.txt"

        def write() -> dict[str, bool]:
            artifact.write_text("complete", encoding="utf-8")
            return {"complete": True}

        result = await _run_builtin_provider_flow(
            database,
            independent_contract(
                "tampered-origin",
                evidence_type="different_type",
                minimum_trust=EvidenceTrustLevel.INDEPENDENT,
                field_path="exists",
            ),
            FileEvidenceProvider(
                artifact,
                evidence_type="file_state",
                clock=lambda: NOW,
            ),
            write,
        )
        assert result.status is TaskStatus.AWAITING_EVIDENCE

        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER evidence_immutable_update")
            encoded = connection.execute(
                "SELECT item_json FROM evidence WHERE task_id = ?",
                ("tampered-origin",),
            ).fetchone()[0]
            item = json.loads(encoded)
            item["type"] = "different_type"
            item["trust_level"] = int(EvidenceTrustLevel.INDEPENDENT)
            item["trust_origin"]["provider_identity"] = "attacker"
            connection.execute(
                "UPDATE evidence SET item_json = ? WHERE task_id = ?",
                (json.dumps(item), "tampered-origin"),
            )

        store = SQLiteStore(database)
        with pytest.raises(CorruptStoreError) as raised:
            store.evidence("tampered-origin")
        assert isinstance(raised.value.__cause__, EvidenceIntegrityError)
        assert store.load_task("tampered-origin").status is not TaskStatus.VERIFIED


def test_worker_collector_cannot_record_independent_evidence() -> None:
    asyncio.run(_worker_collector_cannot_record_independent_evidence())


def test_agent_reported_complete_is_never_success() -> None:
    asyncio.run(_agent_reported_complete_is_never_success())


def test_manual_independent_evidence_object_is_not_trusted() -> None:
    asyncio.run(_manual_independent_evidence_object_is_not_trusted())


def test_agent_content_cannot_satisfy_independent_requirement() -> None:
    asyncio.run(_agent_content_cannot_satisfy_independent_requirement())


def test_worker_owned_registry_cannot_mint_through_public_api() -> None:
    asyncio.run(_worker_owned_registry_cannot_mint_through_public_api())


def test_executor_receipt_cannot_prove_independent_external_outcome() -> None:
    asyncio.run(_executor_receipt_cannot_prove_independent_external_outcome())


def test_builtin_file_provider_enforces_runtime_observation_boundary() -> None:
    asyncio.run(_builtin_file_provider_enforces_runtime_observation_boundary())


def test_trusted_origin_survives_persistence_restart() -> None:
    asyncio.run(_trusted_origin_survives_persistence_restart())


def test_persisted_trust_tampering_cannot_result_in_verified() -> None:
    asyncio.run(_persisted_trust_tampering_cannot_result_in_verified())


def test_agent_claim_only_never_verifies() -> None:
    contract = declared_contract(
        "claim-only",
        minimum_trust=EvidenceTrustLevel.AGENT_CLAIM,
    )
    result = RuleBasedVerifier(clock=lambda: NOW).verify(
        contract,
        {"complete": True},
        EvidenceCollection(
            (
                EvidenceItem(
                    evidence_id="agent-claim",
                    type="external_state",
                    source="agent",
                    collected_at=NOW,
                    payload={"complete": True},
                ),
            )
        ),
    )

    assert result.status.value == "awaiting_evidence"
    assert result.missing_evidence == ("trustworthy_verification_boundary",)


def test_output_only_never_verifies() -> None:
    result = RuleBasedVerifier(clock=lambda: NOW).verify(
        declared_contract("output-only", minimum_trust=None),
        {"complete": True},
        EvidenceCollection(),
    )

    assert result.status.value == "awaiting_evidence"
    assert result.missing_evidence == ("trustworthy_verification_boundary",)


def test_runtime_rejects_custom_verifier_success_without_trusted_evidence() -> None:
    class UnsafeVerifier:
        def verify(self, contract: Any, output: Any, evidence: Any) -> Any:
            del contract, output, evidence
            return VerificationResult(status=VerificationStatus.VERIFIED)

    result = asyncio.run(
        InMemoryRuntime(verifier=UnsafeVerifier()).execute(
            worker_with_report(
                "unsafe-custom-verifier",
                WorkerReport.completed({"complete": True}),
            ),
            declared_contract("unsafe-custom-verifier", minimum_trust=None),
        )
    )

    assert result.status is TaskStatus.AWAITING_EVIDENCE
    assert not result.succeeded


def test_executor_receipt_only_never_verifies() -> None:
    contract = declared_contract(
        "receipt-only-generic",
        minimum_trust=EvidenceTrustLevel.EXECUTOR_RECEIPT,
    )
    receipt = established_evidence(EvidenceTrustLevel.EXECUTOR_RECEIPT)
    result = RuleBasedVerifier(clock=lambda: NOW).verify(
        contract,
        {"complete": True},
        EvidenceCollection((receipt,)),
    )

    assert result.status.value == "awaiting_evidence"
    assert result.missing_evidence == ("trustworthy_verification_boundary",)


@pytest.mark.parametrize(
    "trust_level",
    (EvidenceTrustLevel.RUNTIME_OBSERVED, EvidenceTrustLevel.INDEPENDENT),
)
def test_explicit_trustworthy_boundary_verifies(
    trust_level: EvidenceTrustLevel,
) -> None:
    contract = declared_contract(
        f"trusted-{trust_level.name.lower()}",
        minimum_trust=trust_level,
    )
    result = RuleBasedVerifier(clock=lambda: NOW).verify(
        contract,
        {"complete": True},
        EvidenceCollection((established_evidence(trust_level),)),
    )

    assert result.status.value == "verified"


def test_undeclared_weaker_evidence_cannot_satisfy_stronger_requirement() -> None:
    contract = declared_contract(
        "undeclared-weaker",
        minimum_trust=EvidenceTrustLevel.INDEPENDENT,
    )
    runtime_observation = established_evidence(EvidenceTrustLevel.RUNTIME_OBSERVED)
    undeclared_claim = EvidenceItem(
        evidence_id="undeclared-claim",
        type="different_type",
        source="agent",
        collected_at=NOW,
        payload={"complete": True},
    )
    result = RuleBasedVerifier(clock=lambda: NOW).verify(
        contract,
        {"complete": True},
        EvidenceCollection((runtime_observation, undeclared_claim)),
    )

    assert result.status.value == "awaiting_evidence"
    assert result.missing_evidence == ("external_state",)


@pytest.mark.parametrize(
    ("name", "contract", "evidence"),
    (
        ("zero-evidence", declared_contract("store-zero", minimum_trust=None), None),
        ("output-only", declared_contract("store-output", minimum_trust=None), None),
        (
            "agent-claim",
            declared_contract(
                "store-agent-claim",
                minimum_trust=EvidenceTrustLevel.RUNTIME_OBSERVED,
            ),
            EvidenceItem(
                "store-agent-claim",
                "external_state",
                "agent",
                NOW,
                payload={"complete": True},
            ),
        ),
        (
            "receipt-only",
            declared_contract(
                "store-receipt",
                minimum_trust=EvidenceTrustLevel.EXECUTOR_RECEIPT,
            ),
            established_evidence(EvidenceTrustLevel.EXECUTOR_RECEIPT),
        ),
    ),
)
def test_persistence_rejects_false_verified(
    name: str,
    contract: TaskContract[Any, Any],
    evidence: EvidenceItem | None,
) -> None:
    del name
    with TemporaryDirectory() as directory:
        store, task = verifying_store(Path(directory) / "runtime.db", contract)
        if evidence is not None:
            store.record_evidence(contract.task_id, evidence)
            task = store.load_task(contract.task_id)
        with pytest.raises(InvalidTransitionError):
            store.record_verification(
                contract.task_id,
                expected_version=task.version,
                result=VerificationResult(status=VerificationStatus.VERIFIED),
                final_status=TaskStatus.VERIFIED,
                errors=(),
                occurred_at=NOW,
                wait_token=None,
            )
        assert store.load_task(contract.task_id).status is TaskStatus.VERIFYING


def test_persistence_rejects_mismatched_verification_status() -> None:
    with TemporaryDirectory() as directory:
        contract = independent_contract("store-status-mismatch")
        store, task = verifying_store(Path(directory) / "runtime.db", contract)
        store.record_evidence(
            contract.task_id,
            established_evidence(EvidenceTrustLevel.INDEPENDENT),
        )
        task = store.load_task(contract.task_id)
        with pytest.raises(InvalidTransitionError):
            store.record_verification(
                contract.task_id,
                expected_version=task.version,
                result=VerificationResult(status=VerificationStatus.VERIFIED),
                final_status=TaskStatus.AWAITING_EVIDENCE,
                errors=(),
                occurred_at=NOW,
                wait_token=None,
            )


@pytest.mark.parametrize(
    "trust_level",
    (EvidenceTrustLevel.RUNTIME_OBSERVED, EvidenceTrustLevel.INDEPENDENT),
)
def test_persistence_accepts_valid_trusted_verified(
    trust_level: EvidenceTrustLevel,
) -> None:
    with TemporaryDirectory() as directory:
        contract = independent_contract(
            f"store-valid-{trust_level.name.lower()}",
            minimum_trust=trust_level,
        )
        store, _ = verifying_store(Path(directory) / "runtime.db", contract)
        store.record_evidence(contract.task_id, established_evidence(trust_level))
        task = store.load_task(contract.task_id)
        verified, _ = store.record_verification(
            contract.task_id,
            expected_version=task.version,
            result=VerificationResult(status=VerificationStatus.VERIFIED),
            final_status=TaskStatus.VERIFIED,
            errors=(),
            occurred_at=NOW,
            wait_token=None,
        )
        assert verified.status is TaskStatus.VERIFIED
        assert verified.succeeded


def test_schema_four_evidence_migrates_without_inventing_trusted_origin() -> None:
    with TemporaryDirectory() as directory:
        database = Path(directory) / "legacy.db"
        contract = independent_contract("legacy-trust")
        legacy = SQLiteStore(database, target_schema_version=4)
        legacy.create_task(
            contract,
            correlation_id="legacy-session",
            worker_id="legacy-worker",
            occurred_at=NOW,
        )
        legacy.record_evidence(
            contract.task_id,
            EvidenceItem(
                evidence_id="legacy-independent",
                type="external_state",
                source="legacy-caller",
                collected_at=NOW,
                payload={"complete": True},
                acquisition_method=EvidenceAcquisitionMethod.INDEPENDENT_PROVIDER,
                trust_level=EvidenceTrustLevel.INDEPENDENT,
            ),
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE tasks SET current_state = ? WHERE task_id = ?",
                (TaskStatus.VERIFIED.value, contract.task_id),
            )

        migrated = SQLiteStore(database)
        item = migrated.evidence(contract.task_id)[0]

        assert migrated.schema_version == 7
        assert item.trust_level is EvidenceTrustLevel.AGENT_CLAIM
        assert item.acquisition_method is EvidenceAcquisitionMethod.AGENT_REPORTED
        assert not item.trust_established
        assert migrated.load_task(contract.task_id).status is TaskStatus.INCONCLUSIVE


def test_schema_six_false_verified_is_downgraded_on_migration() -> None:
    with TemporaryDirectory() as directory:
        database = Path(directory) / "legacy-v6.db"
        contract = independent_contract("legacy-v6-false-verified")
        legacy = SQLiteStore(database, target_schema_version=6)
        legacy.create_task(
            contract,
            correlation_id="legacy-session",
            worker_id="legacy-worker",
            occurred_at=NOW,
        )
        verification = legacy.codec.dumps(
            {
                "status": VerificationStatus.VERIFIED.value,
                "criteria": [],
                "missing_evidence": [],
                "contradictory_evidence": [],
                "message": "legacy false positive",
            }
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                """
                UPDATE tasks SET current_state = ?, verification_json = ?,
                    finished_at = ? WHERE task_id = ?
                """,
                (
                    TaskStatus.VERIFIED.value,
                    verification,
                    NOW.isoformat(),
                    contract.task_id,
                ),
            )

        migrated = SQLiteStore(database)

        assert migrated.schema_version == 7
        assert migrated.load_task(contract.task_id).status is TaskStatus.INCONCLUSIVE
