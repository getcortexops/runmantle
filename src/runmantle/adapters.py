"""Small adapters for application-owned async functions and callbacks."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, Protocol, TypeVar

from ._validation import require_non_empty_attributes, require_unique
from .capabilities import CapabilityDeclaration
from .contracts import TaskContract
from .core import TaskContext, TaskResult, WorkerReport
from .recovery import RecoveryPlan
from .telemetry import LifecycleEvent

InputT = TypeVar("InputT")
OutcomeT = TypeVar("OutcomeT")


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    agent_id: str
    name: str
    role: str
    version: str

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("agent_id", "name", "role", "version"),
            prefix="agent identity",
        )


class AgentHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AgentHealth:
    status: AgentHealthStatus
    message: str = ""


@dataclass(frozen=True, slots=True)
class AgentAdapterContract:
    """Identity and declared boundaries for one existing agent adapter."""

    identity: AgentIdentity
    capabilities: tuple[CapabilityDeclaration, ...]
    emits_evidence: bool
    supports_recovery_hooks: bool = False

    def __post_init__(self) -> None:
        if not self.capabilities:
            raise ValueError("an agent adapter must declare at least one capability")
        require_unique(
            (item.name for item in self.capabilities),
            "agent adapter capability names must be unique",
        )


class AdapterRecoveryHooks(Protocol):
    """Optional proposal hook; returned plans still require runtime gates."""

    async def propose_recovery(
        self,
        task: TaskContract[InputT, OutcomeT],
        result: TaskResult[OutcomeT],
    ) -> RecoveryPlan | None:
        """Propose recovery without granting execution authority."""


def _require_recovery_hook_agreement(
    adapter_contract: AgentAdapterContract,
    recovery_hooks: AdapterRecoveryHooks | None,
) -> None:
    """Reject an adapter whose declared recovery support and hook disagree."""

    if adapter_contract.supports_recovery_hooks != (recovery_hooks is not None):
        raise ValueError("adapter recovery declaration and hook must agree")


class AgentAdapter(Protocol[InputT, OutcomeT]):
    """Generic bridge for existing AI agents without framework rewrites."""

    @property
    def adapter_contract(self) -> AgentAdapterContract:
        """Return agent identity and declared capabilities."""

    @property
    def recovery_hooks(self) -> AdapterRecoveryHooks | None:
        """Return optional recovery proposal hooks."""

    async def submit(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        """Submit a task and report output/evidence through Runmantle models."""

    async def health(self) -> AgentHealth:
        """Return adapter-observed health without external assumptions."""


@dataclass(frozen=True, slots=True)
class AgentAdapterWorker(Generic[InputT, OutcomeT]):
    """Expose an AgentAdapter through the native Runmantle Worker protocol."""

    adapter: AgentAdapter[InputT, OutcomeT]

    @property
    def id(self) -> str:
        return self.adapter.adapter_contract.identity.agent_id

    @property
    def name(self) -> str:
        return self.adapter.adapter_contract.identity.name

    @property
    def role(self) -> str:
        return self.adapter.adapter_contract.identity.role

    @property
    def version(self) -> str:
        return self.adapter.adapter_contract.identity.version

    @property
    def capabilities(self) -> tuple[CapabilityDeclaration, ...]:
        return self.adapter.adapter_contract.capabilities

    async def execute(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        return await self.adapter.submit(task, context)


AdapterSubmitHandler = Callable[
    [TaskContract[InputT, OutcomeT], TaskContext],
    Awaitable[WorkerReport[OutcomeT]],
]


@dataclass(frozen=True, slots=True)
class FakeAgentAdapter(Generic[InputT, OutcomeT]):
    """Deterministic AgentAdapter implementation intended for tests/examples."""

    adapter_contract: AgentAdapterContract
    submit_handler: AdapterSubmitHandler[InputT, OutcomeT]
    reported_health: AgentHealth = AgentHealth(AgentHealthStatus.HEALTHY)
    recovery_hooks: AdapterRecoveryHooks | None = None

    def __post_init__(self) -> None:
        _require_recovery_hook_agreement(self.adapter_contract, self.recovery_hooks)

    async def submit(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        return await self.submit_handler(task, context)

    async def health(self) -> AgentHealth:
        return self.reported_health


@dataclass(frozen=True, slots=True)
class FunctionWorker(Generic[InputT, OutcomeT]):
    """Adapt an async typed callable to the Worker protocol."""

    id: str
    name: str
    role: str
    version: str
    capabilities: tuple[CapabilityDeclaration, ...]
    handler: Callable[
        [TaskContract[InputT, OutcomeT], TaskContext],
        Awaitable[WorkerReport[OutcomeT]],
    ]

    def __post_init__(self) -> None:
        require_non_empty_attributes(
            self,
            ("id", "name", "role", "version"),
            prefix="worker",
        )
        if not self.capabilities:
            raise ValueError("a worker must declare at least one capability")

    async def execute(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        return await self.handler(task, context)


@dataclass(frozen=True, slots=True)
class CallbackEventSink:
    callback: Callable[[LifecycleEvent], None]
    capabilities: tuple[CapabilityDeclaration, ...]

    def __post_init__(self) -> None:
        if not self.capabilities:
            raise ValueError("an adapter must explicitly declare its capabilities")

    def emit(self, event: LifecycleEvent) -> None:
        self.callback(event)
