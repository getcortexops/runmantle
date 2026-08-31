"""Deterministic, evidence-backed outcome verification rules."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Generic, Protocol, TypeVar

from .contracts import AcceptanceCriterion, CriterionEvaluation, TaskContract
from .evidence import (
    Clock,
    EvidenceCollection,
    EvidenceItem,
    EvidenceTrustLevel,
    utc_now,
)

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")

# Sentinel distinguishing "field absent" from a field whose value is None.
_MISSING = object()


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    AWAITING_EVIDENCE = "awaiting_evidence"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_RUNTIME_CONFIRMATION = "awaiting_runtime_confirmation"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Evidence-aware verification outcome, separate from a worker report."""

    status: VerificationStatus
    criteria: tuple[CriterionEvaluation, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    contradictory_evidence: tuple[str, ...] = ()
    message: str = ""

    @property
    def passed(self) -> bool:
        return self.status is VerificationStatus.VERIFIED

    @property
    def conclusive(self) -> bool:
        return self.status in {VerificationStatus.VERIFIED, VerificationStatus.FAILED}


_TRUSTWORTHY_BOUNDARY_MESSAGE = (
    "successful verification requires an explicitly declared "
    "runtime-observed or independent evidence requirement"
)


def _declares_trustworthy_requirement(contract: TaskContract[Any, Any]) -> bool:
    """Whether the contract demands proof no worker can produce for itself."""

    return any(
        requirement.minimum_trust_level >= EvidenceTrustLevel.RUNTIME_OBSERVED
        for requirement in contract.required_evidence
    )


def _unmet_evidence_requirements(
    contract: TaskContract[Any, Any],
    evidence: EvidenceCollection,
    decision_time: datetime,
) -> tuple[str, ...]:
    """Evidence types short of their declared minimum count at ``decision_time``."""

    return tuple(
        requirement.evidence_type
        for requirement in contract.required_evidence
        if sum(1 for item in evidence if requirement.accepts(item, at=decision_time))
        < requirement.minimum_count
    )


def enforce_verification_trust_boundary(
    contract: TaskContract[Any, Any],
    evidence: EvidenceCollection,
    result: VerificationResult,
    *,
    decision_time: datetime,
) -> VerificationResult:
    """Prevent any verifier from granting success without declared trusted proof."""

    if result.status is not VerificationStatus.VERIFIED:
        return result
    if not _declares_trustworthy_requirement(contract):
        return VerificationResult(
            status=VerificationStatus.AWAITING_EVIDENCE,
            criteria=result.criteria,
            missing_evidence=("trustworthy_verification_boundary",),
            message=_TRUSTWORTHY_BOUNDARY_MESSAGE,
        )
    missing = _unmet_evidence_requirements(contract, evidence, decision_time)
    if missing:
        return VerificationResult(
            status=VerificationStatus.AWAITING_EVIDENCE,
            criteria=result.criteria,
            missing_evidence=missing,
            message=(
                "a verifier returned success without satisfying the declared "
                "evidence requirements"
            ),
        )
    return result


# Compatibility name retained for the first verification API.
VerificationReport = VerificationResult


class Verifier(Protocol):
    def verify(
        self,
        contract: TaskContract[InputT, OutcomeT],
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> VerificationResult:
        """Verify declared criteria and evidence without trusting worker status."""


Condition = Callable[[OutcomeT, EvidenceCollection], bool | None]


@dataclass(frozen=True, slots=True)
class DeclaredConditionCriterion(Generic[OutcomeT]):
    """A declared deterministic condition; None means evidence is ambiguous."""

    name: str
    description: str
    predicate: Condition[OutcomeT]
    success_message: str = "declared condition satisfied"
    failure_message: str = "declared condition not satisfied"

    def __post_init__(self) -> None:
        _validate_criterion(self.name, self.description)

    def evaluate(
        self,
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        result = self.predicate(output, evidence)
        if result is None:
            return CriterionEvaluation(
                name=self.name,
                passed=False,
                conclusive=False,
                message="declared condition returned an ambiguous result",
            )
        return CriterionEvaluation(
            name=self.name,
            passed=result,
            message=self.success_message if result else self.failure_message,
        )


# Original convenience name remains valid.
PredicateCriterion = DeclaredConditionCriterion


@dataclass(frozen=True, slots=True)
class FieldEqualsCriterion(Generic[OutcomeT]):
    """Require an output or evidence payload field to equal a declared value."""

    name: str
    description: str
    field_path: str
    expected: Any
    evidence_type: str | None = None

    def __post_init__(self) -> None:
        _validate_criterion(self.name, self.description)
        if not self.field_path.strip():
            raise ValueError("field_path must not be empty")

    def evaluate(
        self,
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        if self.evidence_type is None:
            values = (_resolve_field(output, self.field_path),)
        else:
            items = evidence.of_type(self.evidence_type)
            if not items:
                return _inconclusive(self.name, "no matching evidence was available")
            values = tuple(
                _resolve_field(_item_value(item), self.field_path) for item in items
            )
        if any(value is _MISSING for value in values):
            return _inconclusive(
                self.name, f"field {self.field_path!r} was unavailable"
            )
        passed = all(value == self.expected for value in values)
        return CriterionEvaluation(
            name=self.name,
            passed=passed,
            message=(
                f"field {self.field_path!r} matched the expected value"
                if passed
                else f"field {self.field_path!r} contradicted the expected value"
            ),
        )


@dataclass(frozen=True, slots=True)
class CollectionNotEmptyCriterion(Generic[OutcomeT]):
    """Require an output field or a typed evidence collection to be non-empty."""

    name: str
    description: str
    field_path: str | None = None
    evidence_type: str | None = None

    def __post_init__(self) -> None:
        _validate_criterion(self.name, self.description)
        if self.field_path is None and self.evidence_type is None:
            raise ValueError("field_path or evidence_type must be provided")

    def evaluate(
        self,
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        if self.evidence_type is not None:
            value: Any = evidence.of_type(self.evidence_type)
        else:
            value = _resolve_field(output, self.field_path or "")
        if value is _MISSING or not hasattr(value, "__len__"):
            return _inconclusive(
                self.name, "declared collection could not be evaluated"
            )
        passed = len(value) > 0
        return CriterionEvaluation(
            name=self.name,
            passed=passed,
            message="collection was non-empty" if passed else "collection was empty",
        )


@dataclass(frozen=True, slots=True)
class RuntimeConfirmationCriterion(Generic[OutcomeT]):
    """Declare that verification requires a named runtime confirmation."""

    name: str
    description: str
    confirmation_key: str

    def __post_init__(self) -> None:
        _validate_criterion(self.name, self.description)
        if not self.confirmation_key.strip():
            raise ValueError("confirmation_key must not be empty")

    def evaluate(
        self,
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        del output, evidence
        return CriterionEvaluation(
            name=self.name,
            passed=False,
            conclusive=False,
            awaiting_runtime_confirmation=True,
            message=f"runtime confirmation {self.confirmation_key!r} is required",
        )


@dataclass(frozen=True, slots=True)
class ApprovalCriterion(Generic[OutcomeT]):
    """Declare that verification requires an application-owned approval."""

    name: str
    description: str
    approval_key: str

    def __post_init__(self) -> None:
        _validate_criterion(self.name, self.description)
        if not self.approval_key.strip():
            raise ValueError("approval_key must not be empty")

    def evaluate(
        self,
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        del output, evidence
        return CriterionEvaluation(
            name=self.name,
            passed=False,
            conclusive=False,
            awaiting_approval=True,
            message=f"approval {self.approval_key!r} is required",
        )


@dataclass(frozen=True, slots=True)
class RuleBasedVerifier:
    """Evaluate required evidence and declared rules entirely in process."""

    runtime_confirmations: Mapping[str, bool] = field(default_factory=dict)
    approvals: Mapping[str, bool] = field(default_factory=dict)
    clock: Clock = field(default=utc_now, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "runtime_confirmations",
            dict(self.runtime_confirmations),
        )
        object.__setattr__(self, "approvals", dict(self.approvals))

    def verify(
        self,
        contract: TaskContract[InputT, OutcomeT],
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> VerificationResult:
        decision_time = self.clock()
        if not _declares_trustworthy_requirement(contract):
            return VerificationResult(
                status=VerificationStatus.AWAITING_EVIDENCE,
                missing_evidence=("trustworthy_verification_boundary",),
                message=_TRUSTWORTHY_BOUNDARY_MESSAGE,
            )
        missing = _unmet_evidence_requirements(contract, evidence, decision_time)
        if missing:
            return VerificationResult(
                status=VerificationStatus.AWAITING_EVIDENCE,
                missing_evidence=missing,
                message=(
                    "required evidence is missing, expired, or below the "
                    "minimum trust level"
                ),
            )

        eligible_evidence = EvidenceCollection(
            tuple(
                item
                for item in evidence
                if self._eligible_for_declared_requirements(
                    contract,
                    item,
                    decision_time,
                )
            )
        )

        contradictions, ambiguous_evidence = self._evidence_consistency(
            contract,
            eligible_evidence,
        )
        if contradictions:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                contradictory_evidence=contradictions,
                message="required evidence contains contradictory values",
            )
        if ambiguous_evidence:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message=(
                    "required evidence lacks fields needed for a conclusive "
                    f"decision: {', '.join(ambiguous_evidence)}"
                ),
            )

        evaluations = tuple(
            self._evaluate(criterion, output, eligible_evidence)
            for criterion in contract.acceptance_criteria
        )
        if any(item.conclusive and not item.passed for item in evaluations):
            status = VerificationStatus.FAILED
        elif any(item.awaiting_approval for item in evaluations):
            status = VerificationStatus.AWAITING_APPROVAL
        elif any(item.awaiting_runtime_confirmation for item in evaluations):
            status = VerificationStatus.AWAITING_RUNTIME_CONFIRMATION
        elif any(not item.conclusive for item in evaluations):
            status = VerificationStatus.INCONCLUSIVE
        else:
            status = VerificationStatus.VERIFIED
        return VerificationResult(status=status, criteria=evaluations)

    @staticmethod
    def _eligible_for_declared_requirements(
        contract: TaskContract[Any, Any],
        item: EvidenceItem,
        decision_time: datetime,
    ) -> bool:
        matching = tuple(
            requirement
            for requirement in contract.required_evidence
            if requirement.evidence_type == item.type
            and requirement.minimum_trust_level >= EvidenceTrustLevel.RUNTIME_OBSERVED
        )
        return bool(matching) and all(
            requirement.accepts(item, at=decision_time) for requirement in matching
        )

    def _evaluate(
        self,
        criterion: AcceptanceCriterion[OutcomeT],
        output: OutcomeT,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        if isinstance(criterion, ApprovalCriterion):
            approved = self.approvals.get(criterion.approval_key)
            if approved is True:
                return CriterionEvaluation(
                    name=criterion.name,
                    passed=True,
                    message="approval was supplied",
                )
            if approved is False:
                return CriterionEvaluation(
                    name=criterion.name,
                    passed=False,
                    message="approval was rejected",
                )
        if isinstance(criterion, RuntimeConfirmationCriterion):
            confirmed = self.runtime_confirmations.get(criterion.confirmation_key)
            if confirmed is True:
                return CriterionEvaluation(
                    name=criterion.name,
                    passed=True,
                    message="runtime confirmation was supplied",
                )
            if confirmed is False:
                return CriterionEvaluation(
                    name=criterion.name,
                    passed=False,
                    message="runtime confirmation was rejected",
                )
        try:
            return criterion.evaluate(output, evidence)
        except Exception as error:  # noqa: BLE001 - invalid rules are inconclusive
            return _inconclusive(
                criterion.name,
                f"criterion raised {type(error).__name__}: {error}",
            )

    @staticmethod
    def _evidence_consistency(
        contract: TaskContract[Any, Any],
        evidence: EvidenceCollection,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        contradictions: list[str] = []
        ambiguous: list[str] = []
        for requirement in contract.required_evidence:
            items = evidence.of_type(requirement.evidence_type)
            for path in requirement.consistent_fields:
                values = tuple(
                    _resolve_field(_item_value(item), path) for item in items
                )
                if any(value is _MISSING for value in values):
                    ambiguous.append(f"{requirement.evidence_type}.{path}")
                elif values and any(value != values[0] for value in values[1:]):
                    contradictions.append(f"{requirement.evidence_type}.{path}")
        return tuple(contradictions), tuple(ambiguous)


# Original verifier name remains a compatibility alias.
ContractVerifier = RuleBasedVerifier


def _validate_criterion(name: str, description: str) -> None:
    if not name.strip():
        raise ValueError("criterion name must not be empty")
    if not description.strip():
        raise ValueError("criterion description must not be empty")


def _inconclusive(name: str, message: str) -> CriterionEvaluation:
    return CriterionEvaluation(
        name=name,
        passed=False,
        conclusive=False,
        message=message,
    )


def _item_value(item: EvidenceItem) -> Any:
    if item.payload is not None:
        return item.payload
    return item.content


def _resolve_field(value: Any, path: str) -> Any:
    current = value
    for segment in path.split("."):
        if isinstance(current, Mapping):
            if segment not in current:
                return _MISSING
            current = current[segment]
        elif hasattr(current, segment):
            current = getattr(current, segment)
        elif isinstance(current, (list, tuple)) and segment.isdigit():
            index = int(segment)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current
