"""Strongly typed task contracts and deterministic acceptance criteria."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import Any, Generic, Protocol, TypeVar

from ._validation import require_non_empty
from .evidence import EvidenceCollection, EvidenceRequirement

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")
CriterionOutcomeT_contra = TypeVar("CriterionOutcomeT_contra", contravariant=True)


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(StrEnum):
    """Runtime lifecycle states; worker completion is deliberately non-final."""

    PENDING = "pending"
    RUNNING = "running"
    AGENT_REPORTED_COMPLETE = "agent_reported_complete"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    AWAITING_EVIDENCE = "awaiting_evidence"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_RUNTIME_CONFIRMATION = "awaiting_runtime_confirmation"


TaskLifecycleStatus = TaskStatus


@dataclass(frozen=True, slots=True)
class CriterionEvaluation:
    """The deterministic result of evaluating one acceptance criterion."""

    name: str
    passed: bool
    message: str
    conclusive: bool = True
    awaiting_runtime_confirmation: bool = False
    awaiting_approval: bool = False


class AcceptanceCriterion(Protocol[CriterionOutcomeT_contra]):
    """A deterministic check over a reported output and its evidence."""

    @property
    def name(self) -> str:
        """Stable criterion name."""

    @property
    def description(self) -> str:
        """Human-readable acceptance condition."""

    def evaluate(
        self,
        output: CriterionOutcomeT_contra,
        evidence: EvidenceCollection,
    ) -> CriterionEvaluation:
        """Evaluate the criterion without mutating runtime state."""


# Compatibility name retained for the original public API.
SuccessCriterion = AcceptanceCriterion


@dataclass(frozen=True, slots=True)
class TaskContract(Generic[InputT, OutcomeT]):
    """Complete execution and verification contract for one task."""

    task_id: str
    objective: str
    input: InputT
    acceptance_criteria: tuple[AcceptanceCriterion[OutcomeT], ...]
    required_evidence: tuple[EvidenceRequirement, ...]
    allowed_capabilities: frozenset[str]
    risk_level: RiskLevel
    timeout: timedelta
    idempotency_key: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_empty(self.task_id, "task_id")
        require_non_empty(self.objective, "objective")
        if not self.acceptance_criteria:
            raise ValueError("a task contract requires acceptance criteria")
        if self.timeout.total_seconds() <= 0:
            raise ValueError("timeout must be greater than zero")
        require_non_empty(self.idempotency_key, "idempotency_key")
        object.__setattr__(
            self, "allowed_capabilities", frozenset(self.allowed_capabilities)
        )
        object.__setattr__(self, "metadata", dict(self.metadata))
