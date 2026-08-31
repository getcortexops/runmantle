"""Explicit worker and adapter capability declarations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock

from ._validation import require_non_empty
from .contracts import RiskLevel, TaskStatus


class StandardCapability(StrEnum):
    CHECKPOINT = "checkpoint"
    RESUME = "resume"
    CANCEL = "cancel"
    RETRY = "retry"
    ROLLBACK = "rollback"
    INSPECT_HEALTH = "inspect_health"
    REFRESH_SESSION = "refresh_session"


@dataclass(frozen=True, slots=True)
class CapabilityDeclaration:
    """A capability and the runtime constraints under which it is supported."""

    name: str
    description: str
    safety_notes: tuple[str, ...] = ()
    available: bool = True
    recovery_supported: bool = False
    supported_task_states: frozenset[TaskStatus] = field(
        default_factory=lambda: frozenset(TaskStatus)
    )
    requires_idempotency: bool = False
    maximum_risk_level: RiskLevel = RiskLevel.CRITICAL
    requires_approval: bool = False
    requires_runtime_confirmation: bool = True

    def __post_init__(self) -> None:
        require_non_empty(self.name, "capability name")
        require_non_empty(self.description, "capability description")
        object.__setattr__(
            self,
            "supported_task_states",
            frozenset(self.supported_task_states),
        )

    @property
    def requires_pre_action_confirmation(self) -> bool:
        """Whether capability support/safety must be confirmed before execution.

        ``requires_runtime_confirmation`` remains the constructor field for
        compatibility and is deprecated terminology; it never described a
        post-action receipt or final outcome verification.
        """

        return self.requires_runtime_confirmation


# Compatibility name retained for the initial worker API.
Capability = CapabilityDeclaration


class CapabilityRegistry:
    """Thread-safe registry of capabilities confirmed by the local runtime."""

    def __init__(
        self,
        declarations: Iterable[CapabilityDeclaration] = (),
    ) -> None:
        self._declarations: dict[str, CapabilityDeclaration] = {}
        self._lock = Lock()
        for declaration in declarations:
            self.register(declaration)

    def register(self, declaration: CapabilityDeclaration) -> None:
        with self._lock:
            if declaration.name in self._declarations:
                raise ValueError(
                    f"capability {declaration.name!r} is already registered"
                )
            self._declarations[declaration.name] = declaration

    def get(self, name: str) -> CapabilityDeclaration | None:
        with self._lock:
            return self._declarations.get(name)

    def is_available(self, name: str) -> bool:
        declaration = self.get(name)
        return declaration is not None and declaration.available

    def snapshot(self) -> tuple[CapabilityDeclaration, ...]:
        with self._lock:
            return tuple(self._declarations.values())

    @classmethod
    def with_standard_recovery_capabilities(cls) -> CapabilityRegistry:
        return cls(standard_recovery_capabilities())


def standard_recovery_capabilities() -> tuple[CapabilityDeclaration, ...]:
    """Return conservative declarations for the standard recovery vocabulary."""

    failed_states = frozenset(
        {
            TaskStatus.FAILED,
            TaskStatus.INCONCLUSIVE,
            TaskStatus.AWAITING_EVIDENCE,
            TaskStatus.AWAITING_RUNTIME_CONFIRMATION,
        }
    )
    return (
        CapabilityDeclaration(
            name=StandardCapability.CHECKPOINT,
            description="Capture a recoverable task checkpoint.",
            recovery_supported=True,
            supported_task_states=frozenset({TaskStatus.RUNNING}),
            requires_idempotency=True,
            maximum_risk_level=RiskLevel.MEDIUM,
        ),
        CapabilityDeclaration(
            name=StandardCapability.RESUME,
            description="Resume a task from a runtime-confirmed checkpoint.",
            recovery_supported=True,
            supported_task_states=failed_states,
            requires_idempotency=True,
            maximum_risk_level=RiskLevel.MEDIUM,
        ),
        CapabilityDeclaration(
            name=StandardCapability.CANCEL,
            description="Cancel a pending or running task.",
            recovery_supported=True,
            supported_task_states=frozenset({TaskStatus.PENDING, TaskStatus.RUNNING}),
            maximum_risk_level=RiskLevel.HIGH,
        ),
        CapabilityDeclaration(
            name=StandardCapability.RETRY,
            description="Retry an idempotent failed task.",
            recovery_supported=True,
            supported_task_states=failed_states,
            requires_idempotency=True,
            maximum_risk_level=RiskLevel.MEDIUM,
        ),
        CapabilityDeclaration(
            name=StandardCapability.ROLLBACK,
            description="Apply an application-defined compensating action.",
            recovery_supported=True,
            supported_task_states=failed_states,
            requires_idempotency=True,
            maximum_risk_level=RiskLevel.HIGH,
            requires_approval=True,
        ),
        CapabilityDeclaration(
            name=StandardCapability.INSPECT_HEALTH,
            description="Inspect locally available worker health information.",
            recovery_supported=True,
            maximum_risk_level=RiskLevel.LOW,
        ),
        CapabilityDeclaration(
            name=StandardCapability.REFRESH_SESSION,
            description="Refresh an application-owned session through an adapter.",
            recovery_supported=True,
            supported_task_states=failed_states,
            maximum_risk_level=RiskLevel.MEDIUM,
            requires_approval=True,
        ),
    )
