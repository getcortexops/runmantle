"""Optional structural boundary for LangGraph-like async runnables.

This module imports no LangGraph package. It implements only task invocation and
output/evidence mapping; graph-node tracing, checkpoint integration, tool hooks,
and recovery semantics require explicit application adapters.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, Protocol, TypeVar

from .adapters import (
    AdapterRecoveryHooks,
    AgentAdapterContract,
    AgentHealth,
    AgentHealthStatus,
    _require_recovery_hook_agreement,
)
from .contracts import TaskContract
from .core import TaskContext, WorkerReport
from .evidence import EvidenceCollection
from .telemetry import LifecycleEventType

InputT = TypeVar("InputT")
RawT = TypeVar("RawT")
OutcomeT = TypeVar("OutcomeT")
RunnableInputT_contra = TypeVar("RunnableInputT_contra", contravariant=True)
RunnableRawT_co = TypeVar("RunnableRawT_co", covariant=True)


class LangGraphRunnable(Protocol[RunnableInputT_contra, RunnableRawT_co]):
    """Minimal structural shape expected from an injected async runnable."""

    async def ainvoke(
        self,
        input: RunnableInputT_contra,
        config: Mapping[str, Any] | None = None,
    ) -> RunnableRawT_co:
        """Invoke the runnable; supplied by the application or optional package."""


@dataclass(frozen=True, slots=True)
class LangGraphAdapterBoundary(Generic[InputT, RawT, OutcomeT]):
    """Narrow adapter boundary without a core LangGraph dependency."""

    adapter_contract: AgentAdapterContract
    runnable: LangGraphRunnable[InputT, RawT]
    output_mapper: Callable[[RawT], OutcomeT]
    evidence_mapper: Callable[[RawT], EvidenceCollection] | None = None
    config_factory: (
        Callable[
            [TaskContract[InputT, OutcomeT], TaskContext],
            Mapping[str, Any] | None,
        ]
        | None
    ) = None
    health_provider: Callable[[], Awaitable[AgentHealth]] | None = None
    recovery_hooks: AdapterRecoveryHooks | None = None

    def __post_init__(self) -> None:
        _require_recovery_hook_agreement(self.adapter_contract, self.recovery_hooks)

    async def submit(
        self,
        task: TaskContract[InputT, OutcomeT],
        context: TaskContext,
    ) -> WorkerReport[OutcomeT]:
        context.event_emitter.emit(
            "langgraph.invoke.started",
            {"boundary": "structural"},
            event_type=LifecycleEventType.TASK_PROGRESS,
        )
        config = self.config_factory(task, context) if self.config_factory else None
        raw = await self.runnable.ainvoke(task.input, config)
        evidence = (
            self.evidence_mapper(raw)
            if self.evidence_mapper is not None
            else EvidenceCollection()
        )
        context.event_emitter.emit(
            "langgraph.invoke.completed",
            {"boundary": "structural"},
            event_type=LifecycleEventType.TASK_PROGRESS,
        )
        return WorkerReport.completed(
            self.output_mapper(raw),
            evidence=evidence,
        )

    async def health(self) -> AgentHealth:
        if self.health_provider is None:
            return AgentHealth(
                AgentHealthStatus.UNKNOWN,
                "no LangGraph health provider was configured",
            )
        return await self.health_provider()
