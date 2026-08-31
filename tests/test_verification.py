from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from runmantle import (
    Capability,
    CollectionNotEmptyCriterion,
    DeclaredConditionCriterion,
    EvidenceCollection,
    EvidenceItem,
    EvidenceRequirement,
    EvidenceTrustLevel,
    FieldEqualsCriterion,
    FunctionWorker,
    InMemoryRuntime,
    RiskLevel,
    RuleBasedVerifier,
    RuntimeConfirmationCriterion,
    TaskContext,
    TaskContract,
    TaskStatus,
    VerificationStatus,
    WorkerReport,
)
from runmantle.evidence import (
    EvidenceAcquisitionMethod,
    _establish_evidence_origin,
)

COLLECTED_AT = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)


def evidence_item(
    evidence_id: str,
    payload: dict[str, Any],
) -> EvidenceItem:
    item = EvidenceItem(
        evidence_id=evidence_id,
        type="calculation",
        payload=payload,
        source="deterministic-worker",
        collected_at=COLLECTED_AT,
        provenance={"producer": "test-worker", "method": "local-rule"},
        artifact_reference="memory://calculation",
        metadata={"test": True},
    )
    return _establish_evidence_origin(
        item,
        boundary="verification_test_fixture",
        provider_identity="tests.deterministic_verifier:v1",
        provider_configuration={"algorithm": "fixture"},
        trust_level=EvidenceTrustLevel.RUNTIME_OBSERVED,
        acquisition_method=EvidenceAcquisitionMethod.RUNTIME_OBSERVED,
    )


def verification_contract(
    *,
    criteria: tuple[object, ...] | None = None,
    minimum_count: int = 1,
) -> TaskContract[dict[str, Any], dict[str, Any]]:
    declared_criteria = criteria or (
        FieldEqualsCriterion[dict[str, Any]](
            name="evidenced-result",
            description="Every calculation must report result 42.",
            field_path="result",
            expected=42,
            evidence_type="calculation",
        ),
        CollectionNotEmptyCriterion[dict[str, Any]](
            name="records-produced",
            description="The output records collection must not be empty.",
            field_path="records",
        ),
        DeclaredConditionCriterion[dict[str, Any]](
            name="reported-done",
            description="The declared output status must be done.",
            predicate=lambda output, evidence: output.get("status") == "done",
        ),
    )
    return TaskContract(
        task_id="verification-task",
        objective="Produce and verify a deterministic calculation.",
        input={"value": 42},
        acceptance_criteria=declared_criteria,  # type: ignore[arg-type]
        required_evidence=(
            EvidenceRequirement(
                evidence_type="calculation",
                description="Calculation result evidence.",
                minimum_count=minimum_count,
                consistent_fields=("result",),
            ),
        ),
        allowed_capabilities=frozenset({"calculate"}),
        risk_level=RiskLevel.LOW,
        timeout=timedelta(seconds=1),
        idempotency_key="verification-task-42",
    )


class RuleBasedVerifierTest(unittest.TestCase):
    def test_valid_evidence_produces_verified(self) -> None:
        evidence = EvidenceCollection((evidence_item("evidence-1", {"result": 42}),))

        result = RuleBasedVerifier().verify(
            verification_contract(),
            {"status": "done", "records": [42]},
            evidence,
        )

        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertTrue(result.passed)
        self.assertEqual(evidence[0].provenance["method"], "local-rule")
        self.assertEqual(evidence[0].artifact_reference, "memory://calculation")

    def test_missing_evidence_produces_awaiting_evidence(self) -> None:
        result = RuleBasedVerifier().verify(
            verification_contract(),
            {"status": "done", "records": [42]},
            EvidenceCollection(),
        )

        self.assertEqual(result.status, VerificationStatus.AWAITING_EVIDENCE)
        self.assertEqual(result.missing_evidence, ("calculation",))
        self.assertFalse(result.passed)

    def test_contradictory_evidence_produces_failed(self) -> None:
        evidence = EvidenceCollection(
            (
                evidence_item("evidence-1", {"result": 42}),
                evidence_item("evidence-2", {"result": 41}),
            )
        )

        result = RuleBasedVerifier().verify(
            verification_contract(minimum_count=2),
            {"status": "done", "records": [42]},
            evidence,
        )

        self.assertEqual(result.status, VerificationStatus.FAILED)
        self.assertEqual(
            result.contradictory_evidence,
            ("calculation.result",),
        )

    def test_ambiguous_evidence_produces_inconclusive(self) -> None:
        evidence = EvidenceCollection((evidence_item("evidence-1", {"reported": 42}),))

        result = RuleBasedVerifier().verify(
            verification_contract(),
            {"status": "done", "records": [42]},
            evidence,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertFalse(result.conclusive)

    def test_runtime_confirmation_has_a_distinct_status(self) -> None:
        criterion = RuntimeConfirmationCriterion[dict[str, Any]](
            name="side-effect-confirmed",
            description="The runtime must confirm the external effect.",
            confirmation_key="effect-observed",
        )
        task = verification_contract(criteria=(criterion,))
        evidence = EvidenceCollection((evidence_item("evidence-1", {"result": 42}),))

        result = RuleBasedVerifier().verify(
            task,
            {"status": "done", "records": [42]},
            evidence,
        )

        self.assertEqual(
            result.status,
            VerificationStatus.AWAITING_RUNTIME_CONFIRMATION,
        )


class EvidenceBackedRuntimeTest(unittest.IsolatedAsyncioTestCase):
    async def test_agent_reported_success_without_evidence_is_not_verified(
        self,
    ) -> None:
        async def report_success(
            task: TaskContract[dict[str, Any], dict[str, Any]],
            context: TaskContext,
        ) -> WorkerReport[dict[str, Any]]:
            return WorkerReport.completed({"status": "done", "records": [42]})

        worker = FunctionWorker[dict[str, Any], dict[str, Any]](
            id="worker-without-evidence",
            name="Worker without evidence",
            role="test",
            version="1.0.0",
            capabilities=(Capability("calculate", "Calculate a value."),),
            handler=report_success,
        )

        result = await InMemoryRuntime(verifier=RuleBasedVerifier()).execute(
            worker,
            verification_contract(),
        )

        self.assertEqual(result.status, TaskStatus.AWAITING_EVIDENCE)
        self.assertFalse(result.succeeded)
        self.assertIsNotNone(result.final_verification_result)
        self.assertNotEqual(result.status, TaskStatus.VERIFIED)


if __name__ == "__main__":
    unittest.main()
